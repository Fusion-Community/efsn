package recovery

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/rlp"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

func testSigningPolicy(identity SigningIdentity, block *types.Block, count uint64) SigningPolicy {
	owner := common.HexToAddress("0x02")
	if count == 2 {
		owner = identity.Signer
	}
	return SigningPolicy{FirstParent: block.ParentHash(), FirstParentNumber: block.NumberU64() - 1, PurchaseOwner: owner, BlockCount: count, ExecutableSHA256: common.HexToHash("0x03"), ConfigSHA256: common.HexToHash("0x04")}
}

func TestApprovedJournalQuotaAndSequence(t *testing.T) {
	for _, count := range []uint64{1, 2} {
		identity, first, encoded, signer := signingFixture(t)
		policy := testSigningPolicy(identity, first, count)
		path := filepath.Join(t.TempDir(), "journal")
		journal, err := CreateApprovedSigningJournal(path, identity, policy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := journal.Sign(nil, Plan{}, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "approved offline") {
			t.Fatalf("legacy API bypassed policy: %v", err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		block := first
		for stage := uint64(0); stage < count; stage++ {
			journal, err = OpenSigningJournal(path, identity)
			if err != nil {
				t.Fatal(err)
			}
			if journal.policy == nil || *journal.policy != policy {
				t.Fatal("policy did not survive reopen")
			}
			if err := journal.checkPolicySequence(first.WithSeal(&types.Header{ParentHash: common.HexToHash("0xff"), Number: first.Number()})); err == nil {
				t.Fatal("different parent accepted")
			}
			encoded, err = rlp.EncodeToBytes(block)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := journal.signBlock(block, encoded, signer)
			if err != nil {
				t.Fatal(err)
			}
			repeated, err := journal.signBlock(block, encoded, nil)
			if err != nil || repeated.Hash() != signed.Hash() {
				t.Fatalf("completed record was not recovered exactly: %v", err)
			}
			header := block.Header()
			header.ParentHash, header.Number = signed.Hash(), new(big.Int).Add(block.Number(), big.NewInt(1))
			block = types.NewBlockWithHeader(header)
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
		}
		journal, err = OpenSigningJournal(path, identity)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err = rlp.EncodeToBytes(block)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := journal.signBlock(block, encoded, signer); err == nil || !strings.Contains(err.Error(), "quota") {
			t.Fatalf("extra block accepted: %v", err)
		}
		if _, err := journal.Saved(first.ParentHash()); err != nil {
			t.Fatal(err)
		}
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := CreateApprovedSigningJournal(path, identity, policy); err == nil {
			t.Fatal("policy journal recreated")
		}
		t.Logf("%d-block policy retained across reopen; out-of-sequence and extra signatures refused; saved export retained", count)
	}
}

func TestApprovedJournalRefusesInvalidPolicy(t *testing.T) {
	identity, block, _, _ := signingFixture(t)
	for _, change := range []func(*SigningPolicy){
		func(p *SigningPolicy) { p.BlockCount = 0 },
		func(p *SigningPolicy) { p.BlockCount = 3 },
		func(p *SigningPolicy) { p.FirstParentNumber = ^uint64(0) },
		func(p *SigningPolicy) { p.FirstParent = common.Hash{} },
		func(p *SigningPolicy) { p.PurchaseOwner = identity.Signer },
		func(p *SigningPolicy) { p.PurchaseOwner = common.Address{} },
		func(p *SigningPolicy) { p.ExecutableSHA256 = common.Hash{} },
		func(p *SigningPolicy) { p.ConfigSHA256 = common.Hash{} },
	} {
		policy := testSigningPolicy(identity, block, 1)
		change(&policy)
		if journal, err := CreateApprovedSigningJournal(filepath.Join(t.TempDir(), "journal"), identity, policy); err == nil {
			journal.Close()
			t.Fatal("invalid policy accepted")
		}
	}
}

func TestApprovedJournalUnfinishedCannotAdvance(t *testing.T) {
	identity, block, encoded, signer := signingFixture(t)
	path := filepath.Join(t.TempDir(), "journal")
	journal, err := CreateApprovedSigningJournal(path, identity, testSigningPolicy(identity, block, 2))
	if err != nil {
		t.Fatal(err)
	}
	_, err = journal.signBlock(block, encoded, func(accounts.Account, string, []byte) ([]byte, error) {
		return nil, errors.New("signer disconnected")
	})
	if !errors.Is(err, ErrSigningUncertain) {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = OpenSigningJournal(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	header := block.Header()
	header.ParentHash, header.Number = common.HexToHash("0xfe"), new(big.Int).Add(block.Number(), big.NewInt(1))
	next := block.WithSeal(header)
	nextBytes, err := rlp.EncodeToBytes(next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.signBlock(next, nextBytes, signer); !errors.Is(err, ErrSigningUncertain) {
		t.Fatalf("unfinished donation reservation allowed advancement: %v", err)
	}
	if _, err := journal.signBlock(block, encoded, signer); !errors.Is(err, ErrSigningUncertain) {
		t.Fatalf("unfinished donation reservation allowed repeat: %v", err)
	}
}

func TestApprovedJournalRefusesStoredSequenceViolation(t *testing.T) {
	identity, block, encoded, _ := signingFixture(t)
	path := filepath.Join(t.TempDir(), "journal")
	journal, err := CreateApprovedSigningJournal(path, identity, testSigningPolicy(identity, block, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	header := block.Header()
	header.ParentHash = common.HexToHash("0xfe")
	block = block.WithSeal(header)
	encoded, err = rlp.EncodeToBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	data, err := rlp.EncodeToBytes(signingRecord{Unsigned: encoded})
	if err != nil {
		t.Fatal(err)
	}
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put(append([]byte{'p'}, block.ParentHash().Bytes()...), data, &opt.WriteOptions{Sync: true}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if journal, err := OpenSigningJournal(path, identity); err == nil {
		journal.Close()
		t.Fatal("out-of-sequence stored reservation accepted")
	}
}

func TestSigningApprovalExactBytes(t *testing.T) {
	approval := SigningApproval{Version: 1}
	data, err := EncodeSigningApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	checksum := common.Hash(sha256.Sum256(data))
	if _, err := decodeSigningApproval(data, checksum); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSigningApproval(data, common.Hash{}); err == nil {
		t.Fatal("wrong reviewed digest accepted")
	}
	for _, input := range [][]byte{
		append([]byte(" "), data...),
		append(data, []byte("{}")...),
		[]byte(strings.Replace(string(data), `"Version": 1,`, `"Version": 1, "Version": 1,`, 1)),
		[]byte(strings.Replace(string(data), `"Version": 1,`, `"Version": 1, "Unknown": 1,`, 1)),
		[]byte(strings.Replace(string(data), `"Version": 1,`, `"Version": 2,`, 1)),
		make([]byte, (1<<20)+1),
	} {
		if _, err := decodeSigningApproval(input, common.Hash(sha256.Sum256(input))); err == nil {
			t.Fatal("noncanonical, ambiguous, unsupported or oversized approval accepted")
		}
	}
	if _, err := ConfigurationSHA256(nil); err == nil {
		t.Fatal("nil config accepted")
	}
}

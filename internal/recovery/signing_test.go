package recovery

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/rlp"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

func signingFixture(t *testing.T) (SigningIdentity, *types.Block, []byte, datong.SignerFn) {
	t.Helper()
	key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", 1))
	if err != nil {
		t.Fatal(err)
	}
	identity := SigningIdentity{GenesisHash: common.HexToHash("0x01"), ChainID: 32659, Signer: crypto.PubkeyToAddress(key.PublicKey)}
	header := &types.Header{ParentHash: common.HexToHash("0x02"), Number: big.NewInt(15130081), Difficulty: big.NewInt(1), Coinbase: identity.Signer, Time: 1759826750, Extra: make([]byte, 97)}
	block := types.NewBlockWithHeader(header)
	encoded, err := rlp.EncodeToBytes(block)
	if err != nil {
		t.Fatal(err)
	}
	signer := func(account accounts.Account, mime string, payload []byte) ([]byte, error) {
		if account.Address != identity.Signer || mime != "" {
			return nil, fmt.Errorf("unexpected signer request")
		}
		return crypto.Sign(crypto.Keccak256(payload), key)
	}
	return identity, block, encoded, signer
}

func TestSigningJournalReplayAndConflict(t *testing.T) {
	identity, block, encoded, signer := signingFixture(t)
	path := filepath.Join(t.TempDir(), "journal")
	j, err := CreateSigningJournal(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.signBlock(block, encoded, nil); err == nil {
		t.Fatal("nil callback accepted before reservation")
	}
	if _, err := j.Saved(block.ParentHash()); err != leveldb.ErrNotFound {
		t.Fatalf("nil callback left a reservation: %v", err)
	}
	sealed, err := j.signBlock(block, encoded, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenSigningJournal(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	replayed, err := j.signBlock(block, encoded, nil)
	if err != nil || replayed.Hash() != sealed.Hash() {
		t.Fatalf("completed artifact not replayed: %v", err)
	}
	header := block.Header()
	header.Time++
	conflict := block.WithSeal(header)
	different, _ := rlp.EncodeToBytes(conflict)
	if _, err := j.signBlock(conflict, different, signer); !errors.Is(err, ErrSigningConflict) {
		t.Fatalf("conflicting signature allowed: %v", err)
	}
	if _, err := CreateSigningJournal(path, identity); err == nil {
		t.Fatal("journal recreated")
	}
}

func TestSigningJournalTruncatedWAL(t *testing.T) {
	identity, block, encoded, _ := signingFixture(t)
	path := filepath.Join(t.TempDir(), "journal")
	j, err := CreateSigningJournal(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	_, err = j.signBlock(block, encoded, func(accounts.Account, string, []byte) ([]byte, error) {
		return nil, fmt.Errorf("leave reservation pending")
	})
	if !errors.Is(err, ErrSigningUncertain) {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	logs, err := filepath.Glob(filepath.Join(path, "*.log"))
	if err != nil || len(logs) != 1 {
		t.Fatalf("unexpected WAL inventory: %v %v", logs, err)
	}
	info, err := os.Stat(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(logs[0], info.Size()-1); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenSigningJournal(path, identity); err == nil {
		reopened.Close()
		t.Fatal("truncated reservation silently discarded")
	} else {
		t.Logf("truncated reservation refused: %v", err)
	}
}

func TestSigningJournalAmbiguousCallback(t *testing.T) {
	for _, mode := range []string{"error", "short", "wrong_key", "write_failure", "panic"} {
		t.Run(mode, func(t *testing.T) {
			identity, block, encoded, signer := signingFixture(t)
			path := filepath.Join(t.TempDir(), "journal")
			j, err := CreateSigningJournal(path, identity)
			if err != nil {
				t.Fatal(err)
			}
			callback := func(account accounts.Account, mime string, payload []byte) ([]byte, error) {
				signature, err := signer(account, mime, payload)
				switch mode {
				case "error":
					return signature, fmt.Errorf("ambiguous external signer failure")
				case "short":
					return signature[:64], nil
				case "wrong_key":
					key, _ := crypto.HexToECDSA(fmt.Sprintf("%064x", 2))
					return crypto.Sign(crypto.Keccak256(payload), key)
				case "write_failure":
					j.db.Close()
				case "panic":
					panic("signer disconnected after signing")
				}
				return signature, err
			}
			func() {
				defer func() {
					if recovered := recover(); recovered != nil && mode != "panic" {
						t.Fatal(recovered)
					}
				}()
				if _, err := j.signBlock(block, encoded, callback); !errors.Is(err, ErrSigningUncertain) {
					t.Fatalf("failed callback was not quarantined: %v", err)
				}
			}()
			j.Close()
			j, err = OpenSigningJournal(path, identity)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			if _, err := j.signBlock(block, encoded, signer); !errors.Is(err, ErrSigningUncertain) {
				t.Fatalf("ambiguous attempt retried: %v", err)
			}
		})
	}
}

func TestSigningJournalIdentityAndCorruption(t *testing.T) {
	identity, block, encoded, _ := signingFixture(t)
	path := filepath.Join(t.TempDir(), "journal")
	if _, err := OpenSigningJournal(path, identity); err == nil {
		t.Fatal("missing journal silently initialized")
	}
	j, err := CreateSigningJournal(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []SigningIdentity{
		{GenesisHash: common.HexToHash("0x03"), ChainID: identity.ChainID, Signer: identity.Signer},
		{GenesisHash: identity.GenesisHash, ChainID: 1, Signer: identity.Signer},
		{GenesisHash: identity.GenesisHash, ChainID: identity.ChainID, Signer: common.HexToAddress("0x03")},
	} {
		if unexpected, err := OpenSigningJournal(path, wrong); err == nil {
			unexpected.Close()
			t.Fatal("wrong signing identity accepted")
		}
	}
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := rlp.EncodeToBytes(signingRecord{Unsigned: encoded, Signature: []byte{1}})
	if err := db.Put(append([]byte{'p'}, block.ParentHash().Bytes()...), record, &opt.WriteOptions{Sync: true}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if unexpected, err := OpenSigningJournal(path, identity); err == nil {
		unexpected.Close()
		t.Fatal("corrupt signature accepted on open")
	}
}

func TestSigningJournalProcessLock(t *testing.T) {
	identity, _, _, _ := signingFixture(t)
	path := filepath.Join(t.TempDir(), "journal")
	j, err := CreateSigningJournal(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	command := signingChild(t, path, "lock")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("second process lock: %v\n%s", err, output)
	}
}

func TestSigningJournalProcessCuts(t *testing.T) {
	for _, stage := range []string{"before_reservation", "key_opened_before_reservation", "after_reservation", "after_signature", "after_completion"} {
		t.Run(stage, func(t *testing.T) {
			identity, block, encoded, signer := signingFixture(t)
			path := filepath.Join(t.TempDir(), "journal")
			j, err := CreateSigningJournal(path, identity)
			if err != nil {
				t.Fatal(err)
			}
			j.Close()
			command := signingChild(t, path, stage)
			stdout, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			command.Stderr = &stderr
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			ready := make(chan bool, 1)
			go func() {
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					if scanner.Text() == "SIGNING-CUT" {
						ready <- true
						return
					}
				}
				ready <- false
			}()
			var reached bool
			select {
			case reached = <-ready:
			case <-time.After(30 * time.Second):
			}
			command.Process.Kill()
			command.Wait()
			if !reached {
				t.Fatalf("child never reached %s: %s", stage, stderr.String())
			}
			j, err = OpenSigningJournal(path, identity)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			calls := 0
			callback := func(account accounts.Account, mime string, payload []byte) ([]byte, error) {
				calls++
				return signer(account, mime, payload)
			}
			sealed, err := j.signBlock(block, encoded, callback)
			if stage == "after_reservation" || stage == "after_signature" {
				if !errors.Is(err, ErrSigningUncertain) || calls != 0 || sealed != nil {
					t.Fatalf("ambiguous crash retried: calls=%d error=%v", calls, err)
				}
			} else if err != nil || ((stage == "before_reservation" || stage == "key_opened_before_reservation") && calls != 1) || (stage == "after_completion" && calls != 0) {
				t.Fatalf("wrong recovery: calls=%d error=%v", calls, err)
			}
			if stage == "after_completion" {
				want, err := os.ReadFile(path + ".signed.rlp")
				if err != nil {
					t.Fatal(err)
				}
				got, _ := rlp.EncodeToBytes(sealed)
				if !bytes.Equal(got, want) {
					t.Fatal("completed artifact changed after kill")
				}
			}
			t.Logf("forced termination at %s: new signer calls=%d, outcome=%v", stage, calls, err)
		})
	}
}

func signingChild(t *testing.T, path, stage string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestSigningJournalChild$", "-test.timeout=45s")
	command.Env = append(os.Environ(), "FUSION_SIGNING_JOURNAL_TEST="+path, "FUSION_SIGNING_CUT_TEST="+stage)
	return command
}

func TestSigningJournalChild(t *testing.T) {
	path, stage := os.Getenv("FUSION_SIGNING_JOURNAL_TEST"), os.Getenv("FUSION_SIGNING_CUT_TEST")
	if path == "" {
		t.Skip("subprocess helper")
	}
	identity, block, encoded, signer := signingFixture(t)
	j, err := OpenSigningJournal(path, identity)
	if stage == "lock" {
		if err == nil {
			j.Close()
			t.Fatal("another process opened the locked journal")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	cut := func() {
		fmt.Fprintln(os.Stdout, "SIGNING-CUT")
		select {}
	}
	if stage == "before_reservation" {
		cut()
	}
	if stage == "key_opened_before_reservation" {
		keyPath := path + ".encrypted-test-key.json"
		encryptedTestKey(t, keyPath, 1)
		_, err := j.signWithPreflight(block, encoded, func(account accounts.Account, payload []byte) (*signingSession, error) {
			session, err := openKeystoreSigner(keyPath, account, payload, func() ([]byte, error) { return []byte("public test password"), nil })
			if err != nil {
				return nil, err
			}
			cut()
			return session, nil
		})
		t.Fatalf("preflight child returned: %v", err)
	}
	sealed, err := j.signBlock(block, encoded, func(account accounts.Account, mime string, payload []byte) ([]byte, error) {
		if stage == "after_reservation" {
			cut()
		}
		signature, err := signer(account, mime, payload)
		if err != nil {
			t.Fatal(err)
		}
		if stage == "after_signature" {
			cut()
		}
		return signature, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := rlp.EncodeToBytes(sealed)
	if err := os.WriteFile(path+".signed.rlp", data, 0600); err != nil {
		t.Fatal(err)
	}
	cut()
}

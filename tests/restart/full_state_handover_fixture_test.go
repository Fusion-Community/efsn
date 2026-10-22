package restart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

type fullStateHandoverFunding struct {
	Source      common.Hash
	Parent      *types.Header
	Donation    common.Address
	Successor   common.Address
	Liquid      string
	Nonce       uint64
	Differences []fullStateDifference
}

func prepareFullStateHandover(t *testing.T, directory string) {
	t.Helper()
	prepareFullStateCopy(t, directory)
	var original fullStateFixtureLedger
	encoded, err := os.ReadFile(filepath.Join(directory, "fixture.json"))
	requireNoError(t, err)
	requireNoError(t, json.Unmarshal(encoded, &original))
	db, err := rawdb.NewLevelDBDatabase(filepath.Join(directory, "chaindata"), 256, 128, "handover-prepare", false)
	requireNoError(t, err)
	defer db.Close()
	cache := state.NewDatabase(db)
	s, err := state.New(original.Parent.Root, original.Parent.MixDigest, cache)
	requireNoError(t, err)
	keyBytes := make([]byte, 32)
	keyBytes[31] = 2
	key, err := crypto.ToECDSA(keyBytes)
	requireNoError(t, err)
	owner := crypto.PubkeyToAddress(key.PublicKey)
	donation := common.HexToAddress("0xa3ce60d2dbf51afa0ab106df1c44a2e48853817a")
	if s.Exist(owner) || !s.Exist(donation) || s.GetBalance(common.SystemAssetID, donation).String() != "12020102000000000000000" || s.GetNonce(donation) != 0 || len(s.GetCode(donation)) != 0 || len(s.GetAllTimeLockBalances(donation)) != 0 {
		t.Fatal("unexpected donation funding or test-key collision")
	}
	ledger := fullStateHandoverFunding{Source: original.Parent.Hash(), Donation: donation, Successor: owner, Liquid: s.GetBalance(common.SystemAssetID, donation).String(), Nonce: s.GetNonce(donation)}
	s.SetBalance(donation, common.SystemAssetID, new(big.Int))
	s.SetBalance(owner, common.SystemAssetID, decimal(t, ledger.Liquid))
	s.SetNonce(owner, ledger.Nonce)
	header := types.CopyHeader(original.Parent)
	header.Root, err = s.Commit(false)
	requireNoError(t, err)
	requireNoError(t, cache.TrieDB().Commit(header.Root, false, nil))
	ledger.Parent = header
	ledger.Differences, err = fullStateDifferences(cache, original.Parent.Root, header.Root)
	requireNoError(t, err)
	requireNoError(t, validateHandoverFunding(ledger))
	parent := rawdb.ReadBlock(db, original.Parent.Hash(), header.Number.Uint64())
	if parent == nil {
		t.Fatal("missing intermediate synthetic parent")
	}
	block := parent.WithSeal(header)
	rawdb.WriteBlock(db, block)
	rawdb.WriteTd(db, block.Hash(), block.NumberU64(), rawdb.ReadTd(db, parent.Hash(), parent.NumberU64()))
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), rawdb.ReadRawReceipts(db, parent.Hash(), parent.NumberU64()))
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadHeaderHash(db, block.Hash())
	rawdb.WriteHeadFastBlockHash(db, block.Hash())
	requireNoError(t, writeStateExportJSON(filepath.Join(directory, "handover.json"), ledger))
	t.Logf("donation substitution debit=credit=%s nonce=%d changedAccounts=%d syntheticParent=%s root=%s", ledger.Liquid, ledger.Nonce, len(ledger.Differences), header.Hash().Hex(), header.Root.Hex())
}

func validateHandoverFunding(ledger fullStateHandoverFunding) error {
	if ledger.Donation == ledger.Successor || len(ledger.Differences) != 2 {
		return fmt.Errorf("expected two distinct funding accounts")
	}
	seen := make(map[common.Hash]bool)
	for _, difference := range ledger.Differences {
		if seen[difference.AccountKey] {
			return fmt.Errorf("duplicate funding difference")
		}
		seen[difference.AccountKey] = true
		var before state.Account
		switch difference.AccountKey {
		case crypto.Keccak256Hash(ledger.Donation.Bytes()):
			if err := rlp.DecodeBytes(difference.Before, &before); err != nil {
				return err
			}
			if before.Nonce != ledger.Nonce {
				return fmt.Errorf("funding nonce mismatch")
			}
			matched := false
			for i, asset := range before.BalancesHash {
				if asset == common.SystemAssetID {
					if before.BalancesVal[i].String() != ledger.Liquid {
						return fmt.Errorf("funding credit differs from debit")
					}
					before.BalancesVal[i] = new(big.Int)
					matched = true
				}
			}
			if !matched {
				return fmt.Errorf("missing funding asset")
			}
		case crypto.Keccak256Hash(ledger.Successor.Bytes()):
			amount, ok := new(big.Int).SetString(ledger.Liquid, 10)
			if !ok || amount.Sign() <= 0 || len(difference.Before) != 0 {
				return fmt.Errorf("invalid new synthetic funding")
			}
			before = state.Account{Nonce: ledger.Nonce, BalancesHash: []common.Hash{common.SystemAssetID}, BalancesVal: []*big.Int{amount}, Root: types.EmptyRootHash, CodeHash: crypto.Keccak256(nil)}
		default:
			return fmt.Errorf("unexpected funding account")
		}
		encoded, err := rlp.EncodeToBytes(&before)
		if err != nil {
			return err
		}
		if !bytes.Equal(encoded, difference.After) {
			return fmt.Errorf("unapproved funding field change at %s", difference.AccountKey.Hex())
		}
	}
	return nil
}

func openFullStateHandover(t *testing.T, directory string) (*fixture, fullStateFixtureLedger, fullStateHandoverFunding) {
	t.Helper()
	var funding fullStateHandoverFunding
	encoded, err := os.ReadFile(filepath.Join(directory, "handover.json"))
	requireNoError(t, err)
	requireNoError(t, json.Unmarshal(encoded, &funding))
	requireNoError(t, validateHandoverFunding(funding))
	f, original := openFullStateFixture(t, directory)
	requireNoError(t, validateFullStateSubstitution(original))
	if funding.Source != original.Parent.Hash() || funding.Parent == nil || f.parent.Hash() != funding.Parent.Hash() {
		t.Fatal("handover fixture identity mismatch")
	}
	return f, original, funding
}

func selectHandoverSuccessor(t *testing.T, f *fixture, funding fullStateHandoverFunding) {
	t.Helper()
	keyBytes := make([]byte, 32)
	keyBytes[31] = 2
	key, err := crypto.ToECDSA(keyBytes)
	requireNoError(t, err)
	if crypto.PubkeyToAddress(key.PublicKey) != funding.Successor {
		t.Fatal("unexpected successor test key")
	}
	f.owner, f.key = funding.Successor, key
}

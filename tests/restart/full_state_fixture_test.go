package restart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/common/hexutil"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/core/vm"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/ethdb"
	"github.com/FusionFoundation/efsn/v5/rlp"
	"github.com/FusionFoundation/efsn/v5/trie"
)

type fullStateDifference struct {
	AccountKey common.Hash
	Before     hexutil.Bytes
	After      hexutil.Bytes
}

type fullStateFixtureLedger struct {
	Source            *types.Header
	Parent            *types.Header
	OriginalOwner     common.Address
	SyntheticOwner    common.Address
	Liquid            string
	Locks             *common.TimeLock
	Nonce             uint64
	ReassignedTickets []common.Hash
	Differences       []fullStateDifference
}

func fullStateDifferences(db state.Database, before, after common.Hash) ([]fullStateDifference, error) {
	a, err := db.OpenTrie(before)
	if err != nil {
		return nil, err
	}
	b, err := db.OpenTrie(after)
	if err != nil {
		return nil, err
	}
	changes := make(map[common.Hash]*fullStateDifference)
	for direction := 0; direction < 2; direction++ {
		left, right := a, b
		if direction == 1 {
			left, right = b, a
		}
		difference, _ := trie.NewDifferenceIterator(left.NodeIterator(nil), right.NodeIterator(nil))
		iterator := trie.NewIterator(difference)
		for iterator.Next() {
			key := common.BytesToHash(iterator.Key)
			if changes[key] == nil {
				changes[key] = &fullStateDifference{AccountKey: key}
			}
			if direction == 0 {
				changes[key].After = common.CopyBytes(iterator.Value)
			} else {
				changes[key].Before = common.CopyBytes(iterator.Value)
			}
		}
		if iterator.Err != nil {
			return nil, iterator.Err
		}
	}
	result := make([]fullStateDifference, 0, len(changes))
	for _, change := range changes {
		result = append(result, *change)
	}
	sort.Slice(result, func(i, j int) bool { return bytes.Compare(result[i].AccountKey[:], result[j].AccountKey[:]) < 0 })
	return result, nil
}

func initializeFullStateFixture(t *testing.T, db ethdb.Database, identity stateExportIdentity, context *fullStateContext) fullStateFixtureLedger {
	t.Helper()
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	key, err := crypto.ToECDSA(keyBytes)
	requireNoError(t, err)
	owner := crypto.PubkeyToAddress(key.PublicKey)
	original := common.HexToAddress("0x9fc4c40e50f902b9aa641b4a32ebaafa5c9386a1")
	cache := state.NewDatabase(db)
	statedb, err := state.New(identity.Head.Root, identity.Head.MixDigest, cache)
	requireNoError(t, err)
	if statedb.Exist(owner) {
		t.Fatal("synthetic key collision in preserved state")
	}
	if !statedb.Exist(original) {
		t.Fatal("original funding account absent")
	}
	ledger := fullStateFixtureLedger{Source: identity.Head, OriginalOwner: original, SyntheticOwner: owner, Liquid: statedb.GetBalance(common.SystemAssetID, original).String(), Locks: new(common.TimeLock).Set(statedb.GetTimeLockBalance(common.SystemAssetID, original)), Nonce: statedb.GetNonce(original)}
	tickets, err := statedb.AllTickets()
	requireNoError(t, err)
	expectedTickets := tickets.ToMap()
	for id, ticket := range expectedTickets {
		if ticket.Owner == original {
			ledger.ReassignedTickets = append(ledger.ReassignedTickets, id)
		}
	}
	sort.Slice(ledger.ReassignedTickets, func(i, j int) bool {
		return bytes.Compare(ledger.ReassignedTickets[i][:], ledger.ReassignedTickets[j][:]) < 0
	})
	if len(ledger.ReassignedTickets) == 0 {
		t.Fatal("no historical tickets for synthetic signer")
	}
	for _, id := range ledger.ReassignedTickets {
		ticket, err := statedb.GetTicket(id)
		requireNoError(t, err)
		copy := *ticket
		copy.Owner = owner
		requireNoError(t, statedb.RemoveTicket(id))
		requireNoError(t, statedb.AddTicket(copy))
		display := expectedTickets[id]
		display.Owner = owner
		expectedTickets[id] = display
	}
	statedb.SetBalance(original, common.SystemAssetID, new(big.Int))
	statedb.SetTimeLockBalance(original, common.SystemAssetID, new(common.TimeLock))
	statedb.SetBalance(owner, common.SystemAssetID, decimal(t, ledger.Liquid))
	statedb.SetTimeLockBalance(owner, common.SystemAssetID, new(common.TimeLock).Set(ledger.Locks))
	statedb.SetNonce(owner, ledger.Nonce)
	header := types.CopyHeader(identity.Head)
	header.MixDigest, err = statedb.UpdateTickets(header.Number, header.Time)
	requireNoError(t, err)
	tickets, err = statedb.AllTickets()
	requireNoError(t, err)
	if !reflect.DeepEqual(tickets.ToMap(), expectedTickets) {
		t.Fatal("ticket substitution altered more than signer ownership")
	}
	header.Root, err = statedb.Commit(true)
	requireNoError(t, err)
	requireNoError(t, cache.TrieDB().Commit(header.Root, false, nil))
	ledger.Parent = header
	ledger.Differences, err = fullStateDifferences(cache, identity.Head.Root, header.Root)
	requireNoError(t, err)
	requireNoError(t, validateFullStateSubstitution(ledger))
	var genesis types.Header
	requireNoError(t, json.Unmarshal(readRPCObservations(t)[2], &genesis))
	if genesis.Hash() != identity.Genesis {
		t.Fatal("genesis identity mismatch")
	}
	rawdb.WriteBlock(db, types.NewBlockWithHeader(&genesis))
	rawdb.WriteCanonicalHash(db, genesis.Hash(), 0)
	rawdb.WriteTd(db, genesis.Hash(), 0, genesis.Difficulty)
	rawdb.WriteChainConfig(db, genesis.Hash(), identity.Config)
	for _, ancestor := range context.Headers[:255] {
		rawdb.WriteHeader(db, ancestor)
		rawdb.WriteCanonicalHash(db, ancestor.Hash(), ancestor.Number.Uint64())
	}
	parent := context.Parent.WithSeal(header)
	rawdb.WriteBlock(db, parent)
	rawdb.WriteReceipts(db, parent.Hash(), parent.NumberU64(), context.Receipts)
	rawdb.WriteTd(db, parent.Hash(), parent.NumberU64(), context.TotalDifficulty)
	rawdb.WriteCanonicalHash(db, parent.Hash(), parent.NumberU64())
	rawdb.WriteHeadBlockHash(db, parent.Hash())
	rawdb.WriteHeadHeaderHash(db, parent.Hash())
	rawdb.WriteHeadFastBlockHash(db, parent.Hash())
	return ledger
}

func validateFullStateSubstitution(ledger fullStateFixtureLedger) error {
	if len(ledger.Differences) != 3 {
		return fmt.Errorf("expected exactly three changed accounts, got %d", len(ledger.Differences))
	}
	for _, difference := range ledger.Differences {
		var before, after state.Account
		if len(difference.Before) != 0 {
			if err := rlp.DecodeBytes(difference.Before, &before); err != nil {
				return err
			}
		}
		if err := rlp.DecodeBytes(difference.After, &after); err != nil {
			return err
		}
		switch difference.AccountKey {
		case crypto.Keccak256Hash(ledger.OriginalOwner.Bytes()):
			if before.Nonce != ledger.Nonce {
				return fmt.Errorf("funding nonce differs from preserved account")
			}
			matchedBalance, matchedLocks := false, false
			for i, asset := range before.BalancesHash {
				if asset == common.SystemAssetID {
					if before.BalancesVal[i].String() != ledger.Liquid {
						return fmt.Errorf("funding credit differs from original debit")
					}
					matchedBalance = true
					before.BalancesVal[i] = new(big.Int)
				}
			}
			for i, asset := range before.TimeLockBalancesHash {
				if asset == common.SystemAssetID {
					if !before.TimeLockBalancesVal[i].EqualTo(ledger.Locks) {
						return fmt.Errorf("funding locks differ from original debit")
					}
					matchedLocks = true
					before.TimeLockBalancesVal[i] = new(common.TimeLock)
				}
			}
			if !matchedBalance || !matchedLocks {
				return fmt.Errorf("missing original FSN funding fields")
			}
		case crypto.Keccak256Hash(ledger.SyntheticOwner.Bytes()):
			if len(difference.Before) != 0 {
				return fmt.Errorf("synthetic account already existed")
			}
			before = state.Account{Nonce: ledger.Nonce, BalancesHash: []common.Hash{common.SystemAssetID}, BalancesVal: []*big.Int{new(big.Int)}, TimeLockBalancesHash: []common.Hash{common.SystemAssetID}, TimeLockBalancesVal: []*common.TimeLock{ledger.Locks}, Root: types.EmptyRootHash, CodeHash: crypto.Keccak256(nil)}
			if _, ok := before.BalancesVal[0].SetString(ledger.Liquid, 10); !ok {
				return fmt.Errorf("invalid funding amount")
			}
		case crypto.Keccak256Hash(common.TicketKeyAddress.Bytes()):
			if !bytes.Equal(before.CodeHash, ledger.Source.MixDigest.Bytes()) || !bytes.Equal(after.CodeHash, ledger.Parent.MixDigest.Bytes()) {
				return fmt.Errorf("ticket account commitment mismatch")
			}
			before.CodeHash = after.CodeHash
		default:
			return fmt.Errorf("unexpected changed account %s", difference.AccountKey)
		}
		encoded, err := rlp.EncodeToBytes(&before)
		if err != nil {
			return err
		}
		if !bytes.Equal(encoded, difference.After) {
			return fmt.Errorf("unapproved account field change at %s", difference.AccountKey)
		}
	}
	return nil
}

func openFullStateFixture(t *testing.T, directory string) (*fixture, fullStateFixtureLedger) {
	t.Helper()
	var ledger fullStateFixtureLedger
	encoded, err := os.ReadFile(filepath.Join(directory, "fixture.json"))
	requireNoError(t, err)
	requireNoError(t, json.Unmarshal(encoded, &ledger))
	db, err := rawdb.NewLevelDBDatabase(filepath.Join(directory, "chaindata"), 256, 128, "full-state-rehearsal", false)
	requireNoError(t, err)
	config := rawdb.ReadChainConfig(db, rawdb.ReadCanonicalHash(db, 0))
	engine := datong.New(config.DaTong, db)
	chain, err := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, config, engine, vm.Config{}, nil)
	requireNoError(t, err)
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	key, err := crypto.ToECDSA(keyBytes)
	requireNoError(t, err)
	f := &fixture{db: db, chain: chain, engine: engine, key: key, owner: ledger.SyntheticOwner, parent: chain.GetBlockByNumber(ledger.Parent.Number.Uint64())}
	t.Cleanup(func() { chain.Stop(); requireNoError(t, db.Close()) })
	return f, ledger
}

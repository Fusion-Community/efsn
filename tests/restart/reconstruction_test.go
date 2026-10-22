package restart

import (
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
)

type missingStateDatabase struct {
	state.Database
	roots map[common.Hash]bool
}

type missingHeaderChain struct {
	*core.BlockChain
	missing common.Hash
}

func (chain *missingHeaderChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	if hash == chain.missing {
		return nil
	}
	return chain.BlockChain.GetHeader(hash, number)
}

func (db *missingStateDatabase) OpenTrie(root common.Hash) (state.Trie, error) {
	if db.roots[root] {
		return nil, fmt.Errorf("synthetic unavailable state %s", root)
	}
	return db.Database.OpenTrie(root)
}

func TestReconstructionAcrossMissingStates(t *testing.T) {
	for steps := 1; steps <= 4; steps++ {
		for missing := 1; missing <= steps; missing++ {
			t.Run(fmt.Sprintf("step_%d_missing_%d", steps, missing), func(t *testing.T) {
				f := newFixture(t)
				roots := make(map[common.Hash]bool)
				for i := 0; i < steps; i++ {
					timestamp := f.chain.CurrentBlock().Time() + 120
					if i == 2 {
						timestamp = jumpTime
					}
					built := f.buildBlock(t, timestamp, i > 0)
					f.importBlock(t, built)
					if i >= steps-missing {
						roots[built.Root()] = true
					}
				}
				parent := f.chain.CurrentBlock()
				header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), big.NewInt(1)), Coinbase: f.owner, Time: parent.Time() + 120, Difficulty: new(big.Int)}
				expected := types.CopyHeader(header)
				requireNoError(t, f.engine.Prepare(f.chain, expected))
				evictTicketCache(t, parent.MixDigest())
				f.engine.SetStateCache(&missingStateDatabase{Database: state.NewDatabase(f.db), roots: roots})

				err := f.engine.Prepare(f.chain, header)

				requireNoError(t, err)
				if header.Hash() != expected.Hash() || !reflect.DeepEqual(header.GetSelectedTicket(), expected.GetSelectedTicket()) || !reflect.DeepEqual(header.GetRetreatTickets(), expected.GetRetreatTickets()) {
					t.Fatal("reconstructed tickets changed prepared header or ticket selection")
				}
			})
		}
	}
}

func TestReconstructionAtHistoricalExpiryBoundary(t *testing.T) {
	for _, expiry := range []uint64{1759826749, 1759826750, 1759826751} {
		t.Run(fmt.Sprintf("expiry_%d", expiry), func(t *testing.T) {
			f := newFixtureWithExpiry(t, expiry)
			f.importBlock(t, f.buildBlock(t, 1759826750, false))
			parent := f.chain.CurrentBlock()
			header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), big.NewInt(1)), Coinbase: f.owner, Time: parent.Time() + 120, Difficulty: new(big.Int)}
			expected := types.CopyHeader(header)
			requireNoError(t, f.engine.Prepare(f.chain, expected))
			evictTicketCache(t, parent.MixDigest())
			f.engine.SetStateCache(&missingStateDatabase{Database: state.NewDatabase(f.db), roots: map[common.Hash]bool{parent.Root(): true}})

			err := f.engine.Prepare(f.chain, header)

			requireNoError(t, err)
			if header.Hash() != expected.Hash() || !reflect.DeepEqual(header.GetSelectedTicket(), expected.GetSelectedTicket()) || !reflect.DeepEqual(header.GetRetreatTickets(), expected.GetRetreatTickets()) {
				t.Fatal("expiry boundary reconstruction changed prepared header or ticket selection")
			}
		})
	}
}

func TestReconstructionWithMissingAncestorReturnsError(t *testing.T) {
	f := newFixture(t)
	f.importBlock(t, f.buildBlock(t, f.parent.Time()+120, false))
	parent := f.chain.CurrentBlock()
	evictTicketCache(t, parent.MixDigest())
	f.engine.SetStateCache(&missingStateDatabase{Database: state.NewDatabase(f.db), roots: map[common.Hash]bool{parent.Root(): true}})
	chain := &missingHeaderChain{BlockChain: f.chain, missing: f.parent.Hash()}
	header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), big.NewInt(1)), Coinbase: f.owner, Time: parent.Time() + 120, Difficulty: new(big.Int)}
	err := f.engine.Prepare(chain, header)

	if err != consensus.ErrUnknownAncestor {
		t.Fatalf("expected unknown ancestor error, got %v", err)
	}
}

func evictTicketCache(t *testing.T, target common.Hash) {
	t.Helper()
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	statedb, err := state.New(common.Hash{}, common.Hash{}, state.NewDatabase(db))
	requireNoError(t, err)
	for i := int64(0); i < 128; i++ {
		requireNoError(t, statedb.AddTicket(common.Ticket{Owner: common.Address{1}, TicketBody: common.TicketBody{ID: common.BigToHash(big.NewInt(i + 1)), StartTime: 1, ExpireTime: common.TimeLockForever}}))
		_, err := statedb.UpdateTickets(big.NewInt(1), 1)
		requireNoError(t, err)
	}
	if state.GetCachedTickets(target) != nil {
		t.Fatal("target tickets were not evicted")
	}
}

package restart

import (
	"sync"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/core/vm"
)

type pausedImportProcessor struct {
	core.Processor
	number  uint64
	entered chan struct{}
	release chan struct{}
}

func TestHeaderBatchUsesUnstoredParents(t *testing.T) {
	producer := newFixtureWithExpiry(t, common.TimeLockForever)
	receiver := newFixtureWithExpiry(t, common.TimeLockForever)
	advancePurchaseFixture(t, producer, receiver)
	head := receiver.chain.CurrentBlock().Hash()
	batch := roundTripBlocks(t, buildBranch(t, producer, 3, 120))
	headers := blockHeaders(batch)
	headerChain, err := core.NewHeaderChain(receiver.db, receiver.chain.Config(), receiver.engine, func() bool { return false })
	requireNoError(t, err)
	for _, header := range headers {
		if headerChain.GetHeader(header.Hash(), header.Number.Uint64()) != nil {
			t.Fatal("header batch was already present in the receiver")
		}
	}
	_, err = headerChain.ValidateHeaderChain(headers, 1)
	requireNoError(t, err)
	for _, header := range headers {
		if headerChain.GetHeader(header.Hash(), header.Number.Uint64()) != nil {
			t.Fatal("validation unexpectedly persisted a header")
		}
	}
	if receiver.chain.CurrentBlock().Hash() != head {
		t.Fatal("header validation changed the full head")
	}
	t.Log("three linked, unstored headers verified with explicit batch parents without persisting them")
}

func (p *pausedImportProcessor) Process(block *types.Block, state *state.StateDB, config vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	if block.NumberU64() == p.number {
		close(p.entered)
		<-p.release
	}
	return p.Processor.Process(block, state, config)
}

func TestFinalizeParentIsolatedFromConcurrentImport(t *testing.T) {
	producer := newFixtureWithExpiry(t, common.TimeLockForever)
	receiver := newFixtureWithExpiry(t, common.TimeLockForever)
	mining := newFixtureWithExpiry(t, common.TimeLockForever)
	advancePurchaseFixture(t, producer, receiver)
	for number := mining.parent.NumberU64() + 1; number <= producer.chain.CurrentBlock().NumberU64(); number++ {
		mining.importBlock(t, producer.chain.GetBlockByNumber(number))
	}
	batch := roundTripBlocks(t, buildBranch(t, producer, 2, 120))
	buildBranch(t, mining, 1, 121)
	candidate := mining.buildBlockWithTransactions(t, mining.chain.CurrentBlock().Time()+120, nil)
	paused := &pausedImportProcessor{Processor: core.NewStateProcessor(receiver.chain.Config(), receiver.chain, receiver.engine), number: batch[1].NumberU64(), entered: make(chan struct{}), release: make(chan struct{})}
	receiver.chain.SetProcessor(paused)
	var once sync.Once
	unblock := func() { once.Do(func() { close(paused.release) }) }
	defer unblock()
	done := make(chan error, 1)
	go func() { _, err := receiver.chain.InsertChain(batch); done <- err }()
	select {
	case <-paused.entered:
	case err := <-done:
		t.Fatalf("import did not reach its second block: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("import did not reach its second block")
	}
	if err := mining.engine.VerifyHeader(mining.chain, candidate.Header(), true); err != nil {
		t.Errorf("independent header verification used the importing chain's parent: %v", err)
	}
	state, err := mining.chain.State()
	requireNoError(t, err)
	finalized, err := mining.engine.Finalize(mining.chain, candidate.Header(), state, nil, nil, nil)
	if err != nil {
		t.Errorf("independent finalization used the importing chain's parent: %v", err)
	} else if finalized.Root() != candidate.Root() || finalized.MixDigest() != candidate.MixDigest() {
		t.Error("concurrent import changed independently finalized state or tickets")
	}
	unblock()
	select {
	case err := <-done:
		requireNoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("released batch import did not finish")
	}
	if receiver.chain.CurrentBlock().Hash() != batch[1].Hash() {
		t.Fatal("batch import changed its expected head")
	}
	if !t.Failed() {
		t.Log("paused second-block batch processing; independent branch verification/finalization and resumed batch import agree with their own parents")
	}
}

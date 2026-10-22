package restart

import (
	"strings"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/vm"
)

func TestPinnedCheckPointRefusesRivalBranch(t *testing.T) {
	f := newFixtureWithExpiry(t, common.TimeLockForever)
	rival := newFixtureWithExpiry(t, common.TimeLockForever)
	advancePurchaseFixture(t, f, rival)
	canonical := buildBranch(t, f, 3, 120)
	other := buildBranch(t, rival, 4, 150)
	pinned := canonical[1]
	datong.CheckPoints = map[uint64]common.Hash{pinned.NumberU64(): pinned.Hash()}
	t.Cleanup(func() { datong.CheckPoints = nil })
	head := f.chain.CurrentBlock().Hash()

	_, blockErr := f.chain.InsertChain(roundTripBlocks(t, other))
	_, headerErr := f.chain.InsertHeaderChain(blockHeaders(roundTripBlocks(t, other[:2])), 1)
	rival.chain.Stop()
	reopened, err := core.NewBlockChain(rival.db, &core.CacheConfig{TrieDirtyDisabled: true}, rival.chain.Config(), rival.engine, vm.Config{}, nil)
	requireNoError(t, err)
	defer reopened.Stop()

	if blockErr == nil || !strings.Contains(blockErr.Error(), "check point") {
		t.Fatalf("rival block import: %v", blockErr)
	}
	if headerErr == nil || !strings.Contains(headerErr.Error(), "check point") {
		t.Fatalf("rival header import: %v", headerErr)
	}
	if f.chain.CurrentBlock().Hash() != head {
		t.Fatal("canonical head changed")
	}
	if reopened.CurrentBlock().NumberU64() != pinned.NumberU64()-1 {
		t.Fatalf("rival node did not rewind below the check point at startup: head %d", reopened.CurrentBlock().NumberU64())
	}
	t.Logf("rival branch refused at pinned height %d by block and header import; a node on the rival branch rewound to %d at startup", pinned.NumberU64(), reopened.CurrentBlock().NumberU64())
}

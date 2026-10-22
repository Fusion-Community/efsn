package restart

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/FusionFoundation/efsn/v5/consensus/misc"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/core/vm"
	"github.com/FusionFoundation/efsn/v5/internal/ethapi"
	"github.com/FusionFoundation/efsn/v5/rpc"
)

type purchaseBackend struct {
	ethapi.Backend
	chain *core.BlockChain
}

func (b *purchaseBackend) StateAndHeaderByNumber(_ context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	if number != rpc.LatestBlockNumber {
		panic("purchase fixture only supports latest state")
	}
	statedb, err := b.chain.State()
	return statedb, b.chain.CurrentBlock().Header(), err
}

func (f *fixture) newPool(t *testing.T) *core.TxPool {
	t.Helper()
	config := core.DefaultTxPoolConfig
	config.Journal = ""
	pool := core.NewTxPool(config, f.chain.Config(), f.chain)
	t.Cleanup(pool.Stop)
	return pool
}

func (f *fixture) applyPurchase(t *testing.T, tx *types.Transaction) error {
	t.Helper()
	parent := f.chain.CurrentBlock()
	header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), big.NewInt(1)), Time: parent.Time() + 120, GasLimit: parent.GasLimit(), Coinbase: f.owner, Difficulty: new(big.Int), BaseFee: misc.CalcBaseFee(f.chain.Config(), parent.Header())}
	requireNoError(t, f.engine.Prepare(f.chain, header))
	statedb, err := f.chain.State()
	requireNoError(t, err)
	statedb.Prepare(tx.Hash(), 0)
	_, err = core.ApplyTransaction(f.chain.Config(), f.chain, &f.owner, new(core.GasPool).AddGas(header.GasLimit), statedb, header, tx, &header.GasUsed, vm.Config{})
	return err
}

func requireErrorContains(t *testing.T, err error, expected string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected %q, got %v", expected, err)
	}
}

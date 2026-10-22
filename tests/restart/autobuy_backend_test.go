package restart

import (
	"context"
	"errors"
	"math/big"
	"sync/atomic"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/core/vm"
	"github.com/FusionFoundation/efsn/v5/miner"
	"github.com/FusionFoundation/efsn/v5/params"
	"github.com/FusionFoundation/efsn/v5/rpc"
)

type purchaseSubmission struct {
	tx  *types.Transaction
	err error
}

type autoBuyBackend struct {
	*purchaseBackend
	pool        *core.TxPool
	miner       *miner.Miner
	accounts    *accounts.Manager
	owner       common.Address
	mining      atomic.Bool
	submissions chan purchaseSubmission
	initialized chan struct{}
	failNext    atomic.Bool
	buildCalls  atomic.Int32
}

func (b *autoBuyBackend) BlockChain() *core.BlockChain { return b.chain }
func (b *autoBuyBackend) TxPool() *core.TxPool         { return b.pool }
func (b *autoBuyBackend) CurrentBlock() *types.Block   { return b.chain.CurrentBlock() }
func (b *autoBuyBackend) CurrentHeader() *types.Header {
	return b.chain.CurrentBlock().Header()
}
func (b *autoBuyBackend) ChainConfig() *params.ChainConfig { return b.chain.Config() }
func (b *autoBuyBackend) IsMining() bool {
	if b.miner == nil {
		return b.mining.Load()
	}
	return b.miner.Mining()
}
func (b *autoBuyBackend) GetPoolTransactionByPredicate(predicate func(*types.Transaction) bool) *types.Transaction {
	return b.pool.GetByPredicate(predicate)
}
func (b *autoBuyBackend) AccountManager() *accounts.Manager {
	return b.accounts
}
func (b *autoBuyBackend) RPCGasCap() uint64    { return 100000 }
func (b *autoBuyBackend) RPCTxFeeCap() float64 { return 1 }
func (b *autoBuyBackend) Coinbase() (common.Address, error) {
	select {
	case b.initialized <- struct{}{}:
	default:
	}
	return b.owner, nil
}

func (b *autoBuyBackend) StateAndHeaderByNumber(ctx context.Context, number rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	b.buildCalls.Add(1)
	return b.purchaseBackend.StateAndHeaderByNumber(ctx, number)
}

func (b *autoBuyBackend) StateAndHeaderByNumberOrHash(ctx context.Context, number rpc.BlockNumberOrHash) (*state.StateDB, *types.Header, error) {
	if value, ok := number.Number(); !ok || value != rpc.LatestBlockNumber {
		panic("auto-buy fixture only supports latest state")
	}
	return b.purchaseBackend.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
}

func (b *autoBuyBackend) BlockByNumberOrHash(_ context.Context, number rpc.BlockNumberOrHash) (*types.Block, error) {
	if value, ok := number.Number(); !ok || value != rpc.LatestBlockNumber {
		panic("auto-buy fixture only supports latest block")
	}
	return b.chain.CurrentBlock(), nil
}

func (b *autoBuyBackend) SuggestGasTipCap(context.Context) (*big.Int, error) {
	return big.NewInt(1000000000), nil
}

func (b *autoBuyBackend) GetPoolNonce(_ context.Context, address common.Address) (uint64, error) {
	return b.pool.Nonce(address), nil
}

func (b *autoBuyBackend) GetEVM(_ context.Context, msg core.Message, statedb *state.StateDB, header *types.Header, config *vm.Config) (*vm.EVM, func() error, error) {
	blockContext := core.NewEVMBlockContext(header, b.chain, nil)
	txContext := core.NewEVMTxContext(msg)
	return vm.NewEVM(blockContext, txContext, statedb, b.chain.Config(), *config), func() error { return nil }, nil
}

func (b *autoBuyBackend) SendTx(_ context.Context, tx *types.Transaction) error {
	var err error
	if b.failNext.Swap(false) {
		err = errors.New("injected temporary submission failure")
	} else {
		err = b.pool.AddLocal(tx)
	}
	b.submissions <- purchaseSubmission{tx: tx, err: err}
	return err
}

func (b *autoBuyBackend) RebroadcastTx(tx *types.Transaction) {}

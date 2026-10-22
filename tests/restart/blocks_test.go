package restart

import (
	"math/big"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus/misc"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/core/vm"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

func (f *fixture) buildBlock(t *testing.T, timestamp uint64, buy bool) *types.Block {
	t.Helper()
	parent := f.chain.CurrentBlock()
	var txs []*types.Transaction
	if buy {
		end := parent.Time() + 30*24*3600
		if end < ticketEnd {
			end = ticketEnd
		}
		txs = append(txs, f.signPurchase(t, parent.Time(), end))
	}
	return f.buildBlockWithTransactions(t, timestamp, txs)
}

func (f *fixture) signPurchase(t *testing.T, start, end uint64) *types.Transaction {
	t.Helper()
	body, err := rlp.EncodeToBytes(&common.BuyTicketParam{Start: start, End: end})
	requireNoError(t, err)
	data, err := rlp.EncodeToBytes(&common.FSNCallParam{Func: common.BuyTicketFunc, Data: body})
	requireNoError(t, err)
	return f.signPurchaseData(t, data)
}

func (f *fixture) signPurchaseData(t *testing.T, data []byte) *types.Transaction {
	t.Helper()
	parent := f.chain.CurrentBlock()
	statedb, err := f.chain.State()
	requireNoError(t, err)
	price := new(big.Int).Mul(misc.CalcBaseFee(f.chain.Config(), parent.Header()), big.NewInt(2))
	tx, err := types.SignTx(types.NewTransaction(statedb.GetNonce(f.owner), common.FSNCallAddress, new(big.Int), 100000, price, data), types.MakeSigner(f.chain.Config(), new(big.Int).Add(parent.Number(), big.NewInt(1))), f.key)
	requireNoError(t, err)
	return tx
}

func (f *fixture) buildBlockWithTransactions(t *testing.T, timestamp uint64, txs []*types.Transaction) *types.Block {
	t.Helper()
	parent := f.chain.CurrentBlock()
	header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), big.NewInt(1)), Time: timestamp, GasLimit: parent.GasLimit(), Coinbase: f.owner, Difficulty: new(big.Int)}
	header.BaseFee = misc.CalcBaseFee(f.chain.Config(), parent.Header())
	requireNoError(t, f.engine.Prepare(f.chain, header))
	statedb, err := f.chain.StateAt(parent.Root(), parent.MixDigest())
	requireNoError(t, err)
	var receipts types.Receipts
	gasPool := new(core.GasPool).AddGas(header.GasLimit)
	for i, tx := range txs {
		statedb.Prepare(tx.Hash(), i)
		receipt, err := core.ApplyTransaction(f.chain.Config(), f.chain, &f.owner, gasPool, statedb, header, tx, &header.GasUsed, vm.Config{})
		requireNoError(t, err)
		receipts = append(receipts, receipt)
	}
	block, err := f.engine.Finalize(f.chain, header, statedb, txs, nil, receipts)
	requireNoError(t, err)
	signedHeader := block.Header()
	encoded, err := rlp.EncodeToBytes([]interface{}{signedHeader.ParentHash, signedHeader.UncleHash, signedHeader.Coinbase, signedHeader.Root, signedHeader.TxHash, signedHeader.ReceiptHash, signedHeader.Bloom, signedHeader.Difficulty, signedHeader.Number, signedHeader.GasLimit, signedHeader.GasUsed, signedHeader.Time, signedHeader.Extra[:len(signedHeader.Extra)-65], signedHeader.MixDigest, signedHeader.Nonce})
	requireNoError(t, err)
	signature, err := crypto.Sign(crypto.Keccak256(encoded), f.key)
	requireNoError(t, err)
	copy(signedHeader.Extra[len(signedHeader.Extra)-65:], signature)
	return block.WithSeal(signedHeader)
}

func (f *fixture) importBlock(t *testing.T, block *types.Block) {
	t.Helper()
	encoded, err := rlp.EncodeToBytes(block)
	requireNoError(t, err)
	var received types.Block
	requireNoError(t, rlp.DecodeBytes(encoded, &received))
	_, err = f.chain.InsertChain(types.Blocks{&received})
	requireNoError(t, err)
	if f.chain.CurrentBlock().Hash() != received.Hash() {
		t.Fatal("import did not advance the canonical head")
	}
}

func buildBranch(t *testing.T, f *fixture, count int, spacing uint64) types.Blocks {
	t.Helper()
	blocks := make(types.Blocks, 0, count)
	for i := 0; i < count; i++ {
		parent := f.chain.CurrentBlock()
		tx := f.signPurchase(t, parent.Time(), common.TimeLockForever)
		block := f.buildBlockWithTransactions(t, parent.Time()+spacing, []*types.Transaction{tx})
		f.importBlock(t, block)
		blocks = append(blocks, block)
	}
	return blocks
}

func roundTripBlocks(t *testing.T, blocks types.Blocks) types.Blocks {
	t.Helper()
	encoded, err := rlp.EncodeToBytes(blocks)
	requireNoError(t, err)
	var received types.Blocks
	requireNoError(t, rlp.DecodeBytes(encoded, &received))
	return received
}

func blockHeaders(blocks types.Blocks) []*types.Header {
	headers := make([]*types.Header, len(blocks))
	for i, block := range blocks {
		headers[i] = block.Header()
	}
	return headers
}

func advancePurchaseFixture(t *testing.T, f, verifier *fixture) {
	t.Helper()
	jump := uint64(time.Now().Unix()) - 3600
	for i := 0; i < 14; i++ {
		timestamp := f.chain.CurrentBlock().Time() + 120
		if i == 2 {
			timestamp = jump
		}
		var txs []*types.Transaction
		if i > 0 {
			txs = append(txs, f.signPurchase(t, f.chain.CurrentBlock().Time(), common.TimeLockForever))
		}
		block := f.buildBlockWithTransactions(t, timestamp, txs)
		f.importBlock(t, block)
		if verifier != nil {
			verifier.importBlock(t, block)
		}
	}
}

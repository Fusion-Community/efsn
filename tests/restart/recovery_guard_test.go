package restart

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/ethdb"
	"github.com/FusionFoundation/efsn/v5/internal/recovery"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

func recoveryPlan(t *testing.T, signer, buyer *fixture, timestamp, next uint64, tx *types.Transaction) recovery.Plan {
	t.Helper()
	var call common.FSNCallParam
	var purchase common.BuyTicketParam
	requireNoError(t, rlp.DecodeBytes(tx.Data(), &call))
	requireNoError(t, rlp.DecodeBytes(call.Data, &purchase))
	parent := signer.chain.CurrentBlock()
	return recovery.Plan{GenesisHash: signer.chain.Genesis().Hash(), ChainID: signer.chain.Config().ChainID.Uint64(), ParentNumber: parent.NumberU64(), ParentHash: parent.Hash(), Signer: signer.owner, Timestamp: timestamp, NextTimestamp: next, Purchase: recovery.Purchase{Hash: tx.Hash(), Owner: buyer.owner, Nonce: tx.Nonce(), Start: purchase.Start, End: purchase.End}}
}

func TestRecoveryGuard(t *testing.T) {
	original, successor := newHandoverFixture(t, "12020102000000000000000")
	verifier, _ := newHandoverFixture(t, "12020102000000000000000")
	for i := 0; i < 3; i++ {
		parent := original.chain.CurrentBlock()
		timestamp, next := parent.Time()+120, jumpTime
		signer := original
		if i > 0 {
			signer, timestamp, next = successor, jumpTime+uint64(i-1)*120, jumpTime+uint64(i)*120
		}
		tx := successor.signPurchase(t, parent.Time(), ticketEnd)
		plan := recoveryPlan(t, signer, successor, timestamp, next, tx)
		reader, err := recovery.NewReader(original.db)
		requireNoError(t, err)
		before := databaseDigest(t, original.db)
		candidate, err := recovery.Build(reader, plan, types.Transactions{tx})
		requireNoError(t, err)
		if databaseDigest(t, original.db) != before {
			t.Fatal("construction wrote to the database")
		}
		if original.chain.CurrentBlock().Hash() != parent.Hash() {
			t.Fatal("construction changed canonical head")
		}
		header := candidate.Block.Header()
		if !bytes.Equal(header.Extra[len(header.Extra)-65:], make([]byte, 65)) {
			t.Fatal("builder produced a signature")
		}
		block := signer.buildBlockWithTransactions(t, timestamp, []*types.Transaction{tx})
		unsignedHeader := block.Header()
		copy(unsignedHeader.Extra[len(unsignedHeader.Extra)-65:], make([]byte, 65))
		want, err := rlp.EncodeToBytes(block.WithSeal(unsignedHeader))
		requireNoError(t, err)
		got, err := rlp.EncodeToBytes(candidate.Block)
		requireNoError(t, err)
		if !bytes.Equal(got, want) {
			t.Fatal("guarded reader differs from independent construction")
		}
		original.importBlock(t, block)
		verifier.importBlock(t, block)
		t.Logf("guarded stage=%d number=%d selected=%s successor=%s", i+1, block.NumberU64(), candidate.Selected.Hex(), candidate.Ticket.ID.Hex())
	}
}

func TestRecoveryGuardRejects(t *testing.T) {
	original, successor := newHandoverFixture(t, "12020102000000000000000")
	parent := original.chain.CurrentBlock()
	tx := successor.signPurchase(t, parent.Time(), ticketEnd)
	base := recoveryPlan(t, original, successor, parent.Time()+120, jumpTime, tx)
	cases := []struct {
		name, message string
		mutate        func(*recovery.Plan, *types.Transactions)
	}{
		{"omitted", "exactly", func(p *recovery.Plan, txs *types.Transactions) { *txs = nil }},
		{"extra", "exactly", func(p *recovery.Plan, txs *types.Transactions) { *txs = append(*txs, tx) }},
		{"nil", "exactly", func(p *recovery.Plan, txs *types.Transactions) { *txs = types.Transactions{nil} }},
		{"wrong_hash", "exactly", func(p *recovery.Plan, txs *types.Transactions) { p.Purchase.Hash = common.Hash{} }},
		{"wrong_parent", "parent", func(p *recovery.Plan, txs *types.Transactions) { p.ParentHash = common.Hash{} }},
		{"wrong_height", "parent", func(p *recovery.Plan, txs *types.Transactions) { p.ParentNumber++ }},
		{"wrong_genesis", "genesis", func(p *recovery.Plan, txs *types.Transactions) { p.GenesisHash = common.Hash{} }},
		{"wrong_chain", "chain ID", func(p *recovery.Plan, txs *types.Transactions) { p.ChainID++ }},
		{"zero_signer", "explicit signer", func(p *recovery.Plan, txs *types.Transactions) { p.Signer = common.Address{} }},
		{"wrong_owner", "signature", func(p *recovery.Plan, txs *types.Transactions) { p.Purchase.Owner = original.owner }},
		{"wrong_nonce", "nonce", func(p *recovery.Plan, txs *types.Transactions) { p.Purchase.Nonce++ }},
		{"wrong_interval", "interval", func(p *recovery.Plan, txs *types.Transactions) { p.Purchase.End++ }},
		{"backward_time", "block times", func(p *recovery.Plan, txs *types.Transactions) { p.Timestamp = parent.Time() - 1 }},
		{"missing_next_time", "block times", func(p *recovery.Plan, txs *types.Transactions) { p.NextTimestamp = 0 }},
		{"too_short_interval", "remain usable", func(p *recovery.Plan, txs *types.Transactions) { p.Purchase.End = p.Purchase.Start + 29*24*3600 }},
		{"expires_at_next", "remain usable", func(p *recovery.Plan, txs *types.Transactions) { p.NextTimestamp = p.Purchase.End }},
		{"expires_before_next", "remain usable", func(p *recovery.Plan, txs *types.Transactions) { p.NextTimestamp = p.Purchase.End + 1 }},
		{"expired_selected", "selected ticket", func(p *recovery.Plan, txs *types.Transactions) { p.Timestamp, p.NextTimestamp = jumpTime, jumpTime+120 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan, txs := base, types.Transactions{tx}
			test.mutate(&plan, &txs)
			candidate, err := recovery.Build(original.chain, plan, txs)
			requireErrorContains(t, err, test.message)
			if candidate != nil || original.chain.CurrentBlock().Hash() != parent.Hash() {
				t.Fatal("rejected plan returned a candidate or changed the head")
			}
		})
	}
}

func TestRecoveryGuardInsufficientReplacement(t *testing.T) {
	original, successor := newHandoverFixture(t, "5001000000000000000000")
	parent := original.chain.CurrentBlock()
	first := successor.signPurchase(t, parent.Time(), ticketEnd)
	plan := recoveryPlan(t, original, successor, parent.Time()+120, jumpTime, first)
	_, err := recovery.Build(original.chain, plan, types.Transactions{first})
	requireNoError(t, err)
	original.importBlock(t, original.buildBlockWithTransactions(t, plan.Timestamp, []*types.Transaction{first}))
	parent = original.chain.CurrentBlock()
	replacement := successor.signPurchase(t, parent.Time(), ticketEnd)
	plan = recoveryPlan(t, successor, successor, jumpTime, jumpTime+120, replacement)
	candidate, err := recovery.Build(original.chain, plan, types.Transactions{replacement})
	requireErrorContains(t, err, "not enough time lock or asset balance")
	if candidate != nil || original.chain.CurrentBlock().Hash() != parent.Hash() {
		t.Fatal("unfunded replacement produced candidate or advanced head")
	}
}

func databaseDigest(t *testing.T, db ethdb.Database) common.Hash {
	t.Helper()
	hash := sha256.New()
	iterator := db.NewIterator(nil, nil)
	defer iterator.Release()
	for iterator.Next() {
		for _, value := range [][]byte{iterator.Key(), iterator.Value()} {
			requireNoError(t, binary.Write(hash, binary.BigEndian, uint64(len(value))))
			_, err := hash.Write(value)
			requireNoError(t, err)
		}
	}
	requireNoError(t, iterator.Error())
	return common.BytesToHash(hash.Sum(nil))
}

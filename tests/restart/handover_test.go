package restart

import (
	"math/big"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/core/vm"
	"github.com/FusionFoundation/efsn/v5/crypto"
)

func newHandoverFixture(t *testing.T, funding string) (*fixture, *fixture) {
	t.Helper()
	f := newFixture(t)
	keyBytes := make([]byte, 32)
	keyBytes[31] = 2
	key, err := crypto.ToECDSA(keyBytes)
	requireNoError(t, err)
	owner := crypto.PubkeyToAddress(key.PublicKey)
	s, err := f.chain.State()
	requireNoError(t, err)
	if s.Exist(owner) {
		t.Fatal("synthetic successor account collision")
	}
	s.SetBalance(owner, common.SystemAssetID, decimal(t, funding))
	header := f.parent.Header()
	header.Root, err = s.Commit(true)
	requireNoError(t, err)
	requireNoError(t, s.Database().TrieDB().Commit(header.Root, false, nil))
	f.chain.Stop()
	f.parent = types.NewBlockWithHeader(header)
	rawdb.WriteBlock(f.db, f.parent)
	rawdb.WriteTd(f.db, f.parent.Hash(), f.parent.NumberU64(), big.NewInt(1))
	rawdb.WriteCanonicalHash(f.db, f.parent.Hash(), f.parent.NumberU64())
	rawdb.WriteHeadBlockHash(f.db, f.parent.Hash())
	rawdb.WriteHeadHeaderHash(f.db, f.parent.Hash())
	rawdb.WriteHeadFastBlockHash(f.db, f.parent.Hash())
	config := f.chain.Config()
	f.engine = datong.New(config.DaTong, f.db)
	f.chain, err = core.NewBlockChain(f.db, &core.CacheConfig{TrieDirtyDisabled: true}, config, f.engine, vm.Config{}, nil)
	requireNoError(t, err)
	successor := *f
	successor.key, successor.owner = key, owner
	return f, &successor
}

func TestLastTicketHandover(t *testing.T) {
	t.Run("funded_replacements", func(t *testing.T) { runLastTicketHandover(t, "10001000000000000000000", true) })
	t.Run("donation_balance", func(t *testing.T) { runLastTicketHandover(t, "12020102000000000000000", true) })
	t.Run("only_first_ticket_funded", func(t *testing.T) { runLastTicketHandover(t, "5001000000000000000000", false) })
}

func runLastTicketHandover(t *testing.T, funding string, continueMining bool) {
	t.Helper()
	original, successor := newHandoverFixture(t, funding)
	verifier, _ := newHandoverFixture(t, funding)
	for i := 0; i < 4; i++ {
		timestamp := original.chain.CurrentBlock().Time() + 120
		if i == 2 {
			timestamp = jumpTime
		}
		block := original.buildBlock(t, timestamp, i > 0)
		original.importBlock(t, block)
		verifier.importBlock(t, block)
	}
	parent := original.chain.CurrentBlock()
	s, err := original.chain.State()
	requireNoError(t, err)
	tickets, err := s.AllTickets()
	requireNoError(t, err)
	if tickets.NumberOfTickets() != 1 || tickets.NumberOfTicketsByAddress(original.owner) != 1 {
		t.Fatal("handover must begin with only the original signer's last ticket")
	}
	lastTicket := tickets.ToTicketSlice()[0]
	originalNonce := s.GetNonce(original.owner)
	refundBefore := s.GetTimeLockBalance(common.SystemAssetID, original.owner).GetSpendableValue(parent.Time()+120, lastTicket.ExpireTime)
	purchase := successor.signPurchase(t, parent.Time(), parent.Time()+30*24*3600)
	block := original.buildBlockWithTransactions(t, parent.Time()+120, []*types.Transaction{purchase})
	original.importBlock(t, block)
	verifier.importBlock(t, block)
	snapshot, err := datong.NewSnapshotFromHeader(block.Header())
	requireNoError(t, err)
	if snapshot.Selected != lastTicket.ID || len(snapshot.Retreat) != 0 {
		t.Fatal("handover must select original final ticket without retreating another owner")
	}
	s, err = original.chain.State()
	requireNoError(t, err)
	tickets, err = s.AllTickets()
	requireNoError(t, err)
	if tickets.NumberOfTickets() != 1 || tickets.NumberOfTicketsByAddress(original.owner) != 0 || tickets.NumberOfTicketsByAddress(successor.owner) != 1 {
		t.Fatal("last-ticket block did not transfer production eligibility to successor")
	}
	if s.GetNonce(original.owner) != originalNonce {
		t.Fatal("original wallet unexpectedly submitted a transaction")
	}
	refundAfter := s.GetTimeLockBalance(common.SystemAssetID, original.owner).GetSpendableValue(block.Time(), lastTicket.ExpireTime)
	if new(big.Int).Sub(refundAfter, refundBefore).Cmp(decimal(t, "5000000000000000000000")) != 0 {
		t.Fatal("original final ticket's remaining time-lock value was not refunded to its owner")
	}
	retired, err := s.Database().OpenTrie(block.Root())
	requireNoError(t, err)
	retiredAccount, err := retired.TryGet(original.owner.Bytes())
	requireNoError(t, err)
	t.Logf("handover height=%d original=%s successor=%s originalTickets=0 successorTickets=1 originalRefund=5000FSN-time-lock", block.NumberU64(), original.owner.Hex(), successor.owner.Hex())
	if !continueMining {
		before := successor.chain.CurrentBlock()
		tx := successor.signPurchase(t, before.Time(), before.Time()+30*24*3600)
		requireErrorContains(t, successor.applyPurchase(t, tx), "not enough time lock or asset balance")
		if successor.chain.CurrentBlock().Hash() != before.Hash() {
			t.Fatal("unfunded replacement changed canonical head")
		}
		t.Log("5001 FSN initial funding buys the first ticket but cannot fund its replacement before the selection refund")
		return
	}
	for i := 0; i < 4; i++ {
		block = successor.buildBlock(t, successor.chain.CurrentBlock().Time()+120, true)
		successor.importBlock(t, block)
		verifier.importBlock(t, block)
		if successor.chain.CurrentBlock().Root() != verifier.chain.CurrentBlock().Root() {
			t.Fatal("independent successor execution root differs")
		}
	}
	s, err = successor.chain.State()
	requireNoError(t, err)
	tickets, err = s.AllTickets()
	requireNoError(t, err)
	if tickets.NumberOfTickets() != 1 || tickets.NumberOfTicketsByAddress(original.owner) != 0 || tickets.NumberOfTicketsByAddress(successor.owner) != 1 || s.GetNonce(successor.owner) != 5 {
		t.Fatal("successor did not sustain replacement purchases without original signer")
	}
	finalTrie, err := s.Database().OpenTrie(block.Root())
	requireNoError(t, err)
	finalAccount, err := finalTrie.TryGet(original.owner.Bytes())
	requireNoError(t, err)
	if string(finalAccount) != string(retiredAccount) {
		t.Fatal("retired account changed during successor-only production")
	}
	t.Logf("successor-only continuation: four blocks imported independently; retired account unchanged; height=%d root=%s", block.NumberU64(), block.Root().Hex())
}

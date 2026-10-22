package restart

import (
	"bytes"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/internal/recovery"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

func TestRecoveryJournalHandover(t *testing.T) {
	original, successor := newHandoverFixture(t, "12020102000000000000000")
	verifier, _ := newHandoverFixture(t, "12020102000000000000000")
	directory := t.TempDir()
	for _, owner := range []*fixture{original, successor} {
		identity := recovery.SigningIdentity{GenesisHash: original.chain.Genesis().Hash(), ChainID: original.chain.Config().ChainID.Uint64(), Signer: owner.owner}
		journal, err := recovery.CreateSigningJournal(filepath.Join(directory, owner.owner.Hex()), identity)
		requireNoError(t, err)
		requireNoError(t, journal.Close())
	}
	for stage := 0; stage < 3; stage++ {
		parent := original.chain.CurrentBlock()
		signer, timestamp, next := original, parent.Time()+120, jumpTime
		if stage > 0 {
			signer, timestamp, next = successor, jumpTime+uint64(stage-1)*120, jumpTime+uint64(stage)*120
		}
		tx := successor.signPurchase(t, parent.Time(), ticketEnd)
		plan := recoveryPlan(t, signer, successor, timestamp, next, tx)
		candidate, err := recovery.Build(original.chain, plan, types.Transactions{tx})
		requireNoError(t, err)
		reviewed, err := rlp.EncodeToBytes(candidate.Block)
		requireNoError(t, err)
		identity := recovery.SigningIdentity{GenesisHash: plan.GenesisHash, ChainID: plan.ChainID, Signer: plan.Signer}
		journal, err := recovery.OpenSigningJournal(filepath.Join(directory, signer.owner.Hex()), identity)
		requireNoError(t, err)
		var calls int32
		callback := func(account accounts.Account, mime string, payload []byte) ([]byte, error) {
			atomic.AddInt32(&calls, 1)
			return crypto.Sign(crypto.Keccak256(payload), signer.key)
		}
		_, err = journal.Sign(original.chain, plan, types.Transactions{tx}, append(reviewed, 0), callback)
		requireErrorContains(t, err, "reviewed")
		unsafe := plan
		unsafe.NextTimestamp = plan.Purchase.End + 1
		_, err = journal.Sign(original.chain, unsafe, types.Transactions{tx}, reviewed, callback)
		requireErrorContains(t, err, "remain usable")
		wrong := plan
		wrong.ChainID++
		_, err = journal.Sign(original.chain, wrong, types.Transactions{tx}, reviewed, callback)
		requireErrorContains(t, err, "identity")
		if calls != 0 {
			t.Fatal("unreviewed, unsafe or wrong-chain request invoked signer")
		}
		before := databaseDigest(t, original.db)
		var workers sync.WaitGroup
		for i := 0; i < 8; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				if _, err := journal.Sign(original.chain, plan, types.Transactions{tx}, reviewed, callback); err != nil {
					t.Error(err)
				}
			}()
		}
		workers.Wait()
		if calls != 1 || databaseDigest(t, original.db) != before {
			t.Fatal("concurrent signing called the key again or wrote chain data")
		}
		conflict := plan
		conflict.Timestamp += 7
		alternative, err := recovery.Build(original.chain, conflict, types.Transactions{tx})
		requireNoError(t, err)
		alternativeData, err := rlp.EncodeToBytes(alternative.Block)
		requireNoError(t, err)
		_, err = journal.Sign(original.chain, conflict, types.Transactions{tx}, alternativeData, callback)
		requireErrorContains(t, err, "another payload")
		sealed, err := journal.Saved(parent.Hash())
		requireNoError(t, err)
		independent := signer.buildBlockWithTransactions(t, timestamp, []*types.Transaction{tx})
		want, err := rlp.EncodeToBytes(independent)
		requireNoError(t, err)
		got, err := rlp.EncodeToBytes(sealed)
		requireNoError(t, err)
		if !bytes.Equal(got, want) {
			t.Fatal("journal artifact differs from independent signing implementation")
		}
		original.importBlock(t, sealed)
		_, err = journal.Sign(original.chain, plan, types.Transactions{tx}, reviewed, callback)
		requireErrorContains(t, err, "current parent")
		requireNoError(t, journal.Close())
		journal, err = recovery.OpenSigningJournal(filepath.Join(directory, signer.owner.Hex()), identity)
		requireNoError(t, err)
		recovered, err := journal.Saved(parent.Hash())
		requireNoError(t, err)
		requireNoError(t, journal.Close())
		verifier.importBlock(t, recovered)
		if recovered.Hash() != sealed.Hash() || calls != 1 {
			t.Fatal("reopen changed signed artifact or signed again")
		}
		t.Logf("stage=%d height=%d signer=%s signatures=%d hash=%s", stage+1, sealed.NumberU64(), signer.owner.Hex(), calls, sealed.Hash().Hex())
	}
}

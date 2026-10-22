package restart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/params"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

func TestFullStateHandoverAccounting(t *testing.T) {
	directory := os.Getenv("FUSION_RESTART_HANDOVER_AUDIT")
	if directory == "" {
		t.Skip("set FUSION_RESTART_HANDOVER_AUDIT to the prepared fixture ledger directory")
	}
	artifacts := os.Getenv("FUSION_RESTART_HANDOVER_BLOCKS")
	if !filepath.IsAbs(directory) || !filepath.IsAbs(artifacts) {
		t.Fatal("absolute fixture and block artifact paths required")
	}
	auditFullStateHandover(t, directory, artifacts, 10)
}

func auditFullStateHandover(t *testing.T, directory, artifacts string, count int) {
	t.Helper()
	var original fullStateFixtureLedger
	var funding fullStateHandoverFunding
	readHandoverJSON(t, filepath.Join(directory, "fixture.json"), &original)
	readHandoverJSON(t, filepath.Join(directory, "handover.json"), &funding)
	requireNoError(t, validateFullStateSubstitution(original))
	requireNoError(t, validateHandoverFunding(funding))
	var tickets map[common.Hash]common.TicketDisplay
	requireNoError(t, json.Unmarshal(readRPCObservations(t)[7], &tickets))
	addresses := map[common.Hash]common.Address{crypto.Keccak256Hash(funding.Successor.Bytes()): funding.Successor}
	for id, ticket := range tickets {
		if ticket.Owner == original.OriginalOwner {
			ticket.Owner = original.SyntheticOwner
			tickets[id] = ticket
		}
		if ticket.Height == 0 {
			t.Fatal("accounting fixture unexpectedly includes genesis tickets")
		}
		addresses[crypto.Keccak256Hash(ticket.Owner.Bytes())] = ticket.Owner
	}
	previous := funding.Parent
	for i := 1; i <= count; i++ {
		var entry fullStateBlockLedger
		readHandoverJSON(t, filepath.Join(artifacts, fmt.Sprintf("block-%02d.json", i)), &entry)
		encoded, err := os.ReadFile(filepath.Join(artifacts, fmt.Sprintf("block-%02d.rlp", i)))
		requireNoError(t, err)
		var block *types.Block
		requireNoError(t, rlp.DecodeBytes(encoded, &block))
		if block.Hash() != entry.Header.Hash() || entry.Header.ParentHash != previous.Hash() || len(block.Transactions()) != 1 || len(entry.Receipts) != 1 {
			t.Fatal("block/ledger identity or transaction count mismatch")
		}
		tx := block.Transactions()[0]
		sender, err := types.Sender(types.MakeSigner(params.MainnetChainConfig, block.Number()), tx)
		requireNoError(t, err)
		if sender != funding.Successor || tx.Nonce() != uint64(i-1) || tx.To() == nil || *tx.To() != common.FSNCallAddress || tx.Value().Sign() != 0 {
			t.Fatal("unexpected handover transaction sender, nonce or destination")
		}
		expectedSigner := funding.Successor
		if i == 1 {
			expectedSigner = original.SyntheticOwner
		}
		if block.Coinbase() != expectedSigner {
			t.Fatal("unexpected block signer")
		}
		verifyHandoverPurchaseReceipt(t, tx, entry, funding.Successor)
		snapshot, err := datong.NewSnapshotFromHeader(entry.Header)
		requireNoError(t, err)
		selected, ok := tickets[snapshot.Selected]
		if !ok || selected.Owner != expectedSigner {
			t.Fatal("selected ticket does not belong to expected signer")
		}
		fee := new(big.Int).Mul(new(big.Int).SetUint64(entry.Receipts[0].GasUsed), tx.GasPrice())
		if tx.Type() != types.LegacyTxType {
			t.Fatal("accounting requires the observed legacy transaction fee model")
		}
		before, after := make(map[common.Address]state.Account), make(map[common.Address]state.Account)
		for _, difference := range entry.Differences {
			var a, b state.Account
			requireNoError(t, rlp.DecodeBytes(difference.Before, &a))
			requireNoError(t, rlp.DecodeBytes(difference.After, &b))
			if difference.AccountKey == crypto.Keccak256Hash(common.TicketKeyAddress.Bytes()) {
				if !bytes.Equal(a.CodeHash, previous.MixDigest.Bytes()) || !bytes.Equal(b.CodeHash, entry.Header.MixDigest.Bytes()) {
					t.Fatal("ticket store commitment mismatch")
				}
				a.CodeHash = b.CodeHash
			} else {
				address, known := addresses[difference.AccountKey]
				if !known || (i > 1 && address == original.SyntheticOwner) {
					t.Fatal("unexpected changed account or retired owner mutation")
				}
				before[address], after[address] = a, b
				if address == funding.Successor {
					a.Nonce++
				}
				a, b = withoutHandoverFSN(a), withoutHandoverFSN(b)
			}
			expected, err := rlp.EncodeToBytes(a)
			requireNoError(t, err)
			actual, err := rlp.EncodeToBytes(b)
			requireNoError(t, err)
			if !bytes.Equal(expected, actual) {
				t.Fatal("unrelated asset, nonce, notation, code or storage changed")
			}
		}
		points := handoverTimeBoundaries(entry.Header.Time, before, after, tickets, entry.Tickets)
		for _, address := range addresses {
			for point := range points {
				delta := new(big.Int).Sub(handoverValueAt(after[address], entry.Tickets, address, point), handoverValueAt(before[address], tickets, address, point))
				expected := new(big.Int)
				if address == funding.Successor {
					expected.Sub(expected, fee)
				}
				if address == block.Coinbase() {
					expected.Add(expected, fee)
					expected.Add(expected, decimal(t, "312500000000000000"))
				}
				if len(snapshot.Retreat) > 0 {
					penalty, exists := tickets[snapshot.Retreat[0]]
					if !exists {
						t.Fatal("retreat absent from parent tickets")
					}
					if penalty.Owner == address && point >= penalty.StartTime && point <= penalty.ExpireTime {
						expected.Sub(expected, penalty.Value)
					}
				}
				if delta.Cmp(expected) != 0 {
					t.Fatalf("FSN rights mismatch block=%d owner=%s time=%d actual=%s expected=%s", i, address.Hex(), point, delta, expected)
				}
			}
		}
		t.Logf("accounted block=%d height=%d accounts=%d temporalBoundaries=%d tickets=%d feeWei=%s rewardWei=312500000000000000; preserved other assets/code/storage/notation; retired account unchanged=%t", i, block.NumberU64(), len(entry.Differences), len(points), len(entry.Tickets), fee, i > 1)
		previous, tickets = entry.Header, entry.Tickets
	}
	t.Logf("all future FSN rights conserved owner-by-owner across liquid balances, time locks and tickets, except ordinary rewards/fees and first-retreat penalties; blocks=%d totalRewardWei=%s; no database opened", count, new(big.Int).Mul(big.NewInt(int64(count)), decimal(t, "312500000000000000")))
}

func readHandoverJSON(t *testing.T, path string, target interface{}) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	requireNoError(t, err)
	requireNoError(t, json.Unmarshal(encoded, target))
}

func verifyHandoverPurchaseReceipt(t *testing.T, tx *types.Transaction, entry fullStateBlockLedger, owner common.Address) {
	t.Helper()
	receipt := entry.Receipts[0]
	if receipt.Status != types.ReceiptStatusSuccessful || len(receipt.Logs) != 1 || receipt.TxHash != tx.Hash() {
		t.Fatal("purchase receipt failed or ambiguous")
	}
	log := receipt.Logs[0]
	if log.Address != common.FSNCallAddress || len(log.Topics) != 1 || log.Topics[0] != common.BytesToHash([]byte{common.BuyTicketFunc}) {
		t.Fatal("wrong native purchase log")
	}
	var payload map[string]json.RawMessage
	requireNoError(t, json.Unmarshal(log.Data, &payload))
	if _, exists := payload["Error"]; exists {
		t.Fatal("native purchase failed despite receipt status")
	}
	var id common.Hash
	var loggedOwner common.Address
	requireNoError(t, json.Unmarshal(payload["TicketID"], &id))
	requireNoError(t, json.Unmarshal(payload["TicketOwner"], &loggedOwner))
	var envelope common.FSNCallParam
	var purchase common.BuyTicketParam
	requireNoError(t, rlp.DecodeBytes(tx.Data(), &envelope))
	requireNoError(t, rlp.DecodeBytes(envelope.Data, &purchase))
	ticket, exists := entry.Tickets[id]
	if !exists || loggedOwner != owner || ticket.Owner != owner || ticket.Height != entry.Header.Number.Uint64() || envelope.Func != common.BuyTicketFunc || ticket.StartTime != purchase.Start || ticket.ExpireTime != purchase.End || ticket.Value.String() != "5000000000000000000000" {
		t.Fatal("purchase input, native log and resulting ticket differ")
	}
}

func withoutHandoverFSN(account state.Account) state.Account {
	result := account
	result.BalancesHash, result.BalancesVal = nil, nil
	result.TimeLockBalancesHash, result.TimeLockBalancesVal = nil, nil
	for i, asset := range account.BalancesHash {
		if asset != common.SystemAssetID {
			result.BalancesHash = append(result.BalancesHash, asset)
			result.BalancesVal = append(result.BalancesVal, account.BalancesVal[i])
		}
	}
	for i, asset := range account.TimeLockBalancesHash {
		if asset != common.SystemAssetID {
			result.TimeLockBalancesHash = append(result.TimeLockBalancesHash, asset)
			result.TimeLockBalancesVal = append(result.TimeLockBalancesVal, account.TimeLockBalancesVal[i])
		}
	}
	return result
}

func handoverValueAt(account state.Account, tickets map[common.Hash]common.TicketDisplay, owner common.Address, point uint64) *big.Int {
	value := new(big.Int)
	for i, asset := range account.BalancesHash {
		if asset == common.SystemAssetID {
			value.Add(value, account.BalancesVal[i])
		}
	}
	for i, asset := range account.TimeLockBalancesHash {
		if asset == common.SystemAssetID {
			for _, item := range account.TimeLockBalancesVal[i].Items {
				if point >= item.StartTime && point <= item.EndTime {
					value.Add(value, item.Value)
				}
			}
		}
	}
	for _, ticket := range tickets {
		if ticket.Owner == owner && point >= ticket.StartTime && point <= ticket.ExpireTime {
			value.Add(value, ticket.Value)
		}
	}
	return value
}

func handoverTimeBoundaries(start uint64, before, after map[common.Address]state.Account, oldTickets, newTickets map[common.Hash]common.TicketDisplay) map[uint64]bool {
	points := map[uint64]bool{start: true, common.TimeLockForever: true}
	add := func(first, last uint64) {
		if first >= start {
			points[first] = true
		}
		if last >= start {
			points[last] = true
			if last != common.TimeLockForever {
				points[last+1] = true
			}
		}
	}
	for _, accounts := range []map[common.Address]state.Account{before, after} {
		for _, account := range accounts {
			for i, asset := range account.TimeLockBalancesHash {
				if asset == common.SystemAssetID {
					for _, item := range account.TimeLockBalancesVal[i].Items {
						add(item.StartTime, item.EndTime)
					}
				}
			}
		}
	}
	for _, tickets := range []map[common.Hash]common.TicketDisplay{oldTickets, newTickets} {
		for _, ticket := range tickets {
			add(ticket.StartTime, ticket.ExpireTime)
		}
	}
	return points
}

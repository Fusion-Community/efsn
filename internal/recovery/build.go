package recovery

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/consensus/misc"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/core/vm"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

type Plan struct {
	GenesisHash   common.Hash
	ChainID       uint64
	ParentNumber  uint64
	ParentHash    common.Hash
	Signer        common.Address
	Timestamp     uint64
	NextTimestamp uint64
	Purchase      Purchase
}

type Purchase struct {
	Hash  common.Hash
	Owner common.Address
	Nonce uint64
	Start uint64
	End   uint64
}

type Candidate struct {
	Block    *types.Block
	Receipt  *types.Receipt
	Ticket   common.Ticket
	Selected common.Hash
	Retreat  []common.Hash
}

type Chain interface {
	consensus.ChainReader
	core.ChainContext
	StateAt(common.Hash, common.Hash) (*state.StateDB, error)
}

// Build executes one reviewed purchase without committing state or signing a block.
// NextTimestamp is an explicit eligibility horizon, not a guarantee of future uptime.
func Build(chain Chain, plan Plan, txs types.Transactions) (*Candidate, error) {
	parent, err := checkPlan(chain, plan, txs)
	if err != nil {
		return nil, err
	}
	header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number, big.NewInt(1)), Time: plan.Timestamp, GasLimit: parent.GasLimit, Coinbase: plan.Signer, Difficulty: new(big.Int)}
	if chain.Config().IsLondon(header.Number) {
		header.BaseFee = misc.CalcBaseFee(chain.Config(), parent)
	}
	if err := chain.Engine().Prepare(chain, header); err != nil {
		return nil, fmt.Errorf("prepare recovery block: %w", err)
	}
	if header.Time != plan.Timestamp {
		return nil, fmt.Errorf("consensus adjusted planned timestamp from %d to %d", plan.Timestamp, header.Time)
	}
	s, err := chain.StateAt(parent.Root, parent.MixDigest)
	if err != nil {
		return nil, err
	}
	s.Prepare(txs[0].Hash(), 0)
	receipt, err := core.ApplyTransaction(chain.Config(), chain, &plan.Signer, new(core.GasPool).AddGas(header.GasLimit), s, header, txs[0], &header.GasUsed, vm.Config{})
	if err != nil {
		return nil, fmt.Errorf("execute required purchase: %w", err)
	}
	id := crypto.Keccak256Hash(plan.Purchase.Owner.Bytes(), plan.ParentHash.Bytes())
	if err := checkReceipt(receipt, plan.Purchase, id); err != nil {
		return nil, err
	}
	block, err := chain.Engine().Finalize(chain, header, s, txs, nil, types.Receipts{receipt})
	if err != nil {
		return nil, fmt.Errorf("finalize recovery block: %w", err)
	}
	ticket, err := s.GetTicket(id)
	if err != nil {
		return nil, fmt.Errorf("required successor ticket missing: %w", err)
	}
	if ticket.Owner != plan.Purchase.Owner || ticket.Height != block.NumberU64() || ticket.StartTime != plan.Purchase.Start || ticket.ExpireTime != plan.Purchase.End {
		return nil, fmt.Errorf("resulting successor ticket differs from plan")
	}
	if err := s.Error(); err != nil {
		return nil, err
	}
	snapshot, err := datong.NewSnapshotFromHeader(block.Header())
	if err != nil {
		return nil, err
	}
	return &Candidate{Block: block, Receipt: receipt, Ticket: *ticket, Selected: snapshot.Selected, Retreat: snapshot.Retreat}, nil
}

func checkPlan(chain Chain, plan Plan, txs types.Transactions) (*types.Header, error) {
	if _, ok := chain.Engine().(*datong.DaTong); !ok {
		return nil, fmt.Errorf("recovery requires the DaTong engine")
	}
	genesis := chain.GetHeaderByNumber(0)
	if genesis == nil || genesis.Hash() != plan.GenesisHash || plan.ChainID == 0 || chain.Config().ChainID == nil || chain.Config().ChainID.Cmp(new(big.Int).SetUint64(plan.ChainID)) != 0 {
		return nil, fmt.Errorf("genesis or chain ID differs from plan")
	}
	parent := chain.CurrentHeader()
	if parent == nil || parent.Number == nil || !parent.Number.IsUint64() || parent.Number.Uint64() != plan.ParentNumber || parent.Hash() != plan.ParentHash || plan.ParentNumber == ^uint64(0) {
		return nil, fmt.Errorf("current parent differs from plan")
	}
	if plan.Signer == (common.Address{}) || plan.Purchase.Owner == (common.Address{}) {
		return nil, fmt.Errorf("explicit signer and purchase owner required")
	}
	if plan.Timestamp <= parent.Time || plan.Timestamp-parent.Time < datong.MinBlockTime || plan.NextTimestamp <= plan.Timestamp || plan.NextTimestamp-plan.Timestamp < datong.MinBlockTime {
		return nil, fmt.Errorf("planned block times must advance by at least the consensus minimum")
	}
	p := plan.Purchase
	if p.End <= p.Start || p.End-p.Start < 30*24*3600 || p.Start > plan.Timestamp || p.End <= plan.NextTimestamp {
		return nil, fmt.Errorf("purchase must remain usable beyond the next planned timestamp")
	}
	if len(txs) != 1 || txs[0] == nil || txs[0].Hash() != p.Hash {
		return nil, fmt.Errorf("exactly the required purchase transaction must be included")
	}
	tx := txs[0]
	if !tx.Protected() || tx.ChainId().Cmp(chain.Config().ChainID) != 0 || tx.To() == nil || *tx.To() != common.FSNCallAddress || tx.Value().Sign() != 0 || tx.Nonce() != p.Nonce {
		return nil, fmt.Errorf("purchase destination, value, nonce or chain ID differs from plan")
	}
	owner, err := types.Sender(types.MakeSigner(chain.Config(), new(big.Int).Add(parent.Number, big.NewInt(1))), tx)
	if err != nil || owner != p.Owner {
		return nil, fmt.Errorf("purchase signature does not match planned owner")
	}
	var call common.FSNCallParam
	var purchase common.BuyTicketParam
	if err := rlp.DecodeBytes(tx.Data(), &call); err != nil || call.Func != common.BuyTicketFunc {
		return nil, fmt.Errorf("required transaction is not a native ticket purchase")
	}
	if err := rlp.DecodeBytes(call.Data, &purchase); err != nil || purchase.Start != p.Start || purchase.End != p.End {
		return nil, fmt.Errorf("purchase interval differs from plan")
	}
	return parent, nil
}

func checkReceipt(receipt *types.Receipt, purchase Purchase, id common.Hash) error {
	if receipt == nil || receipt.Status != types.ReceiptStatusSuccessful || receipt.TxHash != purchase.Hash || len(receipt.Logs) != 1 {
		return fmt.Errorf("required purchase receipt failed or is ambiguous")
	}
	entry := receipt.Logs[0]
	if entry == nil || entry.Address != common.FSNCallAddress || len(entry.Topics) != 1 || entry.Topics[0] != common.BytesToHash([]byte{common.BuyTicketFunc}) {
		return fmt.Errorf("required native purchase log missing")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(entry.Data, &payload); err != nil {
		return fmt.Errorf("invalid purchase log: %w", err)
	}
	if _, failed := payload["Error"]; failed {
		return fmt.Errorf("native purchase reported an error: %s", payload["Error"])
	}
	var loggedID common.Hash
	var loggedOwner common.Address
	if err := json.Unmarshal(payload["TicketID"], &loggedID); err != nil || loggedID != id {
		return fmt.Errorf("native purchase ticket ID mismatch")
	}
	if err := json.Unmarshal(payload["TicketOwner"], &loggedOwner); err != nil || loggedOwner != purchase.Owner {
		return fmt.Errorf("native purchase owner mismatch")
	}
	return nil
}

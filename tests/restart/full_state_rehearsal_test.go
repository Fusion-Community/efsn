package restart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

type fullStateBlockLedger struct {
	Header      *types.Header
	Receipts    types.Receipts
	Tickets     map[common.Hash]common.TicketDisplay
	Differences []fullStateDifference
}

func TestFullStateRehearsal(t *testing.T) {
	directory := os.Getenv("FUSION_RESTART_FULL_STATE_DIR")
	if directory == "" {
		t.Skip("set FUSION_RESTART_FULL_STATE_DIR to a freshly verified disposable copy")
	}
	if !filepath.IsAbs(directory) || os.Getenv("FUSION_RESTART_CHAINDATA") != "" {
		t.Fatal("absolute disposable path and no backup source environment required")
	}
	requireFullStateCopy(t, directory)
	mode := os.Getenv("FUSION_RESTART_FULL_STATE_MODE")
	t.Logf("full-state mode=%s directory=%s executable=%s", mode, directory, stateExportExecutableHash(t))
	switch mode {
	case "prepare":
		prepareFullStateCopy(t, directory)
	case "produce", "import":
		runFullStateBridge(t, directory, mode)
	case "cold":
		inspectFullStateBridge(t, directory)
	default:
		t.Fatal("mode must be prepare, produce, import or cold")
	}
}

func requireFullStateCopy(t *testing.T, directory string) {
	t.Helper()
	proof, err := os.ReadFile(filepath.Join(directory, "copy-verified.json"))
	requireNoError(t, err)
	var copyProof struct {
		Source         string
		ManifestSHA256 string
		Files          int
	}
	requireNoError(t, json.Unmarshal(proof, &copyProof))
	if filepath.Clean(copyProof.Source) == filepath.Clean(directory) || copyProof.ManifestSHA256 != "a6c86fc58a9f7b482a02b787a337d600e32a447551e45dbe40d210b498341bbf" || copyProof.Files != 230 {
		t.Fatal("disposable copy proof missing or unexpected")
	}
}

func prepareFullStateCopy(t *testing.T, directory string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(directory, "fixture.json")); !os.IsNotExist(err) {
		t.Fatal("fixture already initialized or cannot be inspected")
	}
	var identity stateExportIdentity
	encoded, err := os.ReadFile(filepath.Join(directory, "identity.json"))
	requireNoError(t, err)
	requireNoError(t, json.Unmarshal(encoded, &identity))
	var expected types.Header
	requireNoError(t, json.Unmarshal(readRPCObservations(t)[3], &expected))
	if identity.Format != 1 || identity.Head == nil || identity.Head.Hash() != expected.Hash() || identity.Config == nil {
		t.Fatal("unexpected state identity or active anchor")
	}
	var context fullStateContext
	encoded, err = os.ReadFile("testdata/context.rlp")
	requireNoError(t, err)
	requireNoError(t, rlp.DecodeBytes(encoded, &context))
	requireNoError(t, validateFullStateContext(&context, expected.Hash()))
	db, err := rawdb.NewLevelDBDatabase(filepath.Join(directory, "chaindata"), 256, 128, "full-state-prepare", false)
	requireNoError(t, err)
	defer db.Close()
	if rawdb.ReadCanonicalHash(db, 0) != (common.Hash{}) || rawdb.ReadHeadBlockHash(db) != (common.Hash{}) || rawdb.ReadHeadHeaderHash(db) != (common.Hash{}) || rawdb.ReadHeadFastBlockHash(db) != (common.Hash{}) {
		t.Fatal("copy already contains chain metadata")
	}
	ledger := initializeFullStateFixture(t, db, identity, &context)
	requireNoError(t, writeStateExportJSON(filepath.Join(directory, "fixture.json"), ledger))
	t.Logf("synthetic parent=%s root=%s tickets=%s transferredLiquid=%s nonce=%d reassignedTickets=%d changedAccounts=%d", ledger.Parent.Hash().Hex(), ledger.Parent.Root.Hex(), ledger.Parent.MixDigest.Hex(), ledger.Liquid, ledger.Nonce, len(ledger.ReassignedTickets), len(ledger.Differences))
}

func runFullStateBridge(t *testing.T, directory, mode string) {
	t.Helper()
	f, ledger := openFullStateFixture(t, directory)
	if f.chain.CurrentBlock().Hash() != ledger.Parent.Hash() {
		t.Fatal("bridge must start at the fresh synthetic parent")
	}
	artifacts := os.Getenv("FUSION_RESTART_FULL_STATE_BLOCKS")
	if !filepath.IsAbs(artifacts) {
		t.Fatal("absolute bridge artifact directory required")
	}
	if mode == "produce" {
		requireNoError(t, os.Mkdir(artifacts, 0700))
	}
	for i := 0; i < 8; i++ {
		parent := f.chain.CurrentBlock()
		verifyFullStateContextReads(t, f, parent.Header())
		blockPath := filepath.Join(artifacts, fmt.Sprintf("block-%02d.rlp", i+1))
		ledgerPath := filepath.Join(artifacts, fmt.Sprintf("block-%02d.json", i+1))
		var block *types.Block
		if mode == "produce" {
			timestamp := parent.Time() + 120
			if i == 2 {
				timestamp = jumpTime
			}
			block = f.buildBlock(t, timestamp, i > 0)
			encoded, err := rlp.EncodeToBytes(block)
			requireNoError(t, err)
			file, err := os.OpenFile(blockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			requireNoError(t, err)
			_, err = file.Write(encoded)
			requireNoError(t, err)
			requireNoError(t, file.Close())
		} else {
			encoded, err := os.ReadFile(blockPath)
			requireNoError(t, err)
			requireNoError(t, rlp.DecodeBytes(encoded, &block))
		}
		f.importBlock(t, block)
		entry := captureFullStateBlock(t, f, parent.Root(), block)
		if mode == "produce" {
			requireNoError(t, writeStateExportJSON(ledgerPath, entry))
		} else {
			encoded, err := os.ReadFile(ledgerPath)
			requireNoError(t, err)
			actual, err := json.MarshalIndent(entry, "", "  ")
			requireNoError(t, err)
			if !bytes.Equal(bytes.TrimSpace(encoded), actual) {
				t.Fatal("independent import differs in header, receipts, tickets or complete account differences")
			}
		}
		s, err := f.chain.State()
		requireNoError(t, err)
		t.Logf("step=%d height=%d time=%d hash=%s root=%s tickets=%d changedAccounts=%d liquid=%s nonce=%d", i+1, block.NumberU64(), block.Time(), block.Hash().Hex(), block.Root().Hex(), len(entry.Tickets), len(entry.Differences), s.GetBalance(common.SystemAssetID, f.owner), s.GetNonce(f.owner))
	}
}

func captureFullStateBlock(t *testing.T, f *fixture, parentRoot common.Hash, block *types.Block) fullStateBlockLedger {
	t.Helper()
	s, err := f.chain.StateAt(block.Root(), block.MixDigest())
	requireNoError(t, err)
	tickets, err := s.AllTickets()
	requireNoError(t, err)
	requireNoError(t, state.AddCachedTickets(block.MixDigest(), tickets))
	differences, err := fullStateDifferences(state.NewDatabase(f.db), parentRoot, block.Root())
	requireNoError(t, err)
	receipts := rawdb.ReadReceipts(f.db, block.Hash(), block.NumberU64(), f.chain.Config())
	if len(receipts) != len(block.Transactions()) {
		t.Fatal("receipt count differs from transactions")
	}
	for _, receipt := range receipts {
		if receipt.Status != types.ReceiptStatusSuccessful {
			t.Fatal("recovery purchase failed")
		}
	}
	return fullStateBlockLedger{Header: block.Header(), Receipts: receipts, Tickets: tickets.ToMap(), Differences: differences}
}

func verifyFullStateContextReads(t *testing.T, f *fixture, parent *types.Header) {
	t.Helper()
	next := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number, big.NewInt(1)), Time: parent.Time + 120, Difficulty: big.NewInt(1)}
	context := core.NewEVMBlockContext(next, f.chain, &f.owner)
	if context.ParentTime.Uint64() != parent.Time {
		t.Fatal("missing EVM parent time")
	}
	for depth := uint64(0); depth < 256; depth++ {
		height := parent.Number.Uint64() - depth
		header := f.chain.GetHeaderByNumber(height)
		if header == nil || context.GetHash(height) != header.Hash() {
			t.Fatalf("missing or inconsistent historical context at %d", height)
		}
	}
	if f.chain.GetHeaderByNumber(parent.Number.Uint64()-10) == nil {
		t.Fatal("missing sealing-delay context")
	}
}

func inspectFullStateBridge(t *testing.T, directory string) {
	t.Helper()
	f, ledger := openFullStateFixture(t, directory)
	head := f.chain.CurrentBlock()
	if head.NumberU64() != ledger.Parent.Number.Uint64()+8 {
		t.Fatal("cold head did not retain all eight blocks")
	}
	artifacts := os.Getenv("FUSION_RESTART_FULL_STATE_BLOCKS")
	for i := uint64(1); i <= 8; i++ {
		var expected fullStateBlockLedger
		encoded, err := os.ReadFile(filepath.Join(artifacts, fmt.Sprintf("block-%02d.json", i)))
		requireNoError(t, err)
		requireNoError(t, json.Unmarshal(encoded, &expected))
		block := f.chain.GetBlockByNumber(ledger.Parent.Number.Uint64() + i)
		if block == nil || block.Hash() != expected.Header.Hash() {
			t.Fatal("cold canonical history differs")
		}
		parent := f.chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
		actual := captureFullStateBlock(t, f, parent.Root, block)
		actualJSON, err := json.Marshal(actual)
		requireNoError(t, err)
		expectedJSON, err := json.Marshal(expected)
		requireNoError(t, err)
		if !bytes.Equal(actualJSON, expectedJSON) {
			t.Fatal("cold ledger differs")
		}
	}
	for _, hash := range []common.Hash{rawdb.ReadHeadBlockHash(f.db), rawdb.ReadHeadHeaderHash(f.db), rawdb.ReadHeadFastBlockHash(f.db)} {
		if hash != head.Hash() {
			t.Fatal("cold head markers disagree")
		}
	}
	verifyFullStateContextReads(t, f, head.Header())
	verifyFullStateReconstruction(t, f)
	last := time.Now()
	result, err := inspectState(f.db, head.Root(), func(current stateInspection) {
		if time.Since(last) > 20*time.Second {
			t.Logf("cold full-state progress: %+v", current)
			last = time.Now()
		}
	})
	requireNoError(t, err)
	t.Logf("cold full-state inventory: %+v head=%s root=%s", result, head.Hash().Hex(), head.Root().Hex())
	requireNoError(t, writeStateExportJSON(filepath.Join(directory, "cold-verified.json"), result))
}

func verifyFullStateReconstruction(t *testing.T, f *fixture) {
	t.Helper()
	parent := f.chain.CurrentBlock()
	header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), big.NewInt(1)), Time: parent.Time() + 120, Coinbase: f.owner, Difficulty: new(big.Int)}
	expected := types.CopyHeader(header)
	requireNoError(t, f.engine.Prepare(f.chain, expected))
	roots := make(map[common.Hash]bool)
	for height := f.parent.NumberU64() + 1; height <= parent.NumberU64(); height++ {
		roots[f.chain.GetHeaderByNumber(height).Root] = true
	}
	evictTicketCache(t, parent.MixDigest())
	f.engine.SetStateCache(&missingStateDatabase{Database: state.NewDatabase(f.db), roots: roots})
	requireNoError(t, f.engine.Prepare(f.chain, header))
	if header.Hash() != expected.Hash() || !reflect.DeepEqual(header.GetSelectedTicket(), expected.GetSelectedTicket()) || !reflect.DeepEqual(header.GetRetreatTickets(), expected.GetRetreatTickets()) {
		t.Fatal("full-state reconstruction changed selection")
	}
	t.Logf("reconstructed %d unavailable suffix states back to retained synthetic parent", len(roots))
	roots[f.parent.Root()] = true
	evictTicketCache(t, parent.MixDigest())
	f.engine.SetStateCache(&missingStateDatabase{Database: state.NewDatabase(f.db), roots: roots})
	limited := &missingHeaderChain{BlockChain: f.chain, missing: f.parent.ParentHash()}
	header = &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), big.NewInt(1)), Time: parent.Time() + 120, Coinbase: f.owner, Difficulty: new(big.Int)}
	if err := f.engine.Prepare(limited, header); err != consensus.ErrUnknownAncestor {
		t.Fatalf("missing retained parent/context should fail, got %v", err)
	}
	f.engine.SetStateCache(state.NewDatabase(f.db))
	t.Log("missing retained parent plus historical fallback context fails with unknown ancestor")
}

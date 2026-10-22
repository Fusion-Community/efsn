package restart

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/common/hexutil"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
)

func stateExportExecutableHash(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	requireNoError(t, err)
	return stateExportFileHash(t, executable)
}

func stateExportFileHash(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	requireNoError(t, err)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func TestVerifyStateExport(t *testing.T) {
	directory := os.Getenv("FUSION_RESTART_VERIFY_EXPORT_DIR")
	if directory == "" {
		t.Skip("set FUSION_RESTART_VERIFY_EXPORT_DIR for a separate cold verification process")
	}
	if !filepath.IsAbs(directory) || os.Getenv("FUSION_RESTART_CHAINDATA") != "" {
		t.Fatal("cold verification requires an absolute export path and no source database environment")
	}
	encoded, err := os.ReadFile(filepath.Join(directory, "identity.json"))
	requireNoError(t, err)
	var identity stateExportIdentity
	requireNoError(t, json.Unmarshal(encoded, &identity))
	writerHash := stateExportExecutableHash(t)
	if writer := os.Getenv("FUSION_RESTART_STATE_EXPORT_WRITER"); writer != "" {
		if !filepath.IsAbs(writer) {
			t.Fatal("explicit retained writer binary requires an absolute path")
		}
		writerHash = stateExportFileHash(t, writer)
	}
	values := readRPCObservations(t)
	var expectedHead, expectedGenesis types.Header
	var expectedTickets map[common.Hash]common.TicketDisplay
	var expectedChainID hexutil.Uint64
	requireNoError(t, json.Unmarshal(values[1], &expectedChainID))
	requireNoError(t, json.Unmarshal(values[2], &expectedGenesis))
	requireNoError(t, json.Unmarshal(values[3], &expectedHead))
	requireNoError(t, json.Unmarshal(values[7], &expectedTickets))
	if identity.Format != 1 || identity.Head == nil || identity.Head.Hash() != expectedHead.Hash() || identity.Genesis != expectedGenesis.Hash() || identity.Config == nil || identity.Config.ChainID == nil || identity.Config.ChainID.Uint64() != uint64(expectedChainID) || identity.ExecutableHash != writerHash {
		t.Fatal("export identity does not match the preserved observations and retained executable")
	}
	t.Logf("state verification identities: writer=%s verifier=%s", writerHash, stateExportExecutableHash(t))
	db, err := rawdb.NewLevelDBDatabase(filepath.Join(directory, "chaindata"), 256, 128, "restart-state-verify", true)
	requireNoError(t, err)
	closed := false
	t.Cleanup(func() {
		if !closed {
			requireNoError(t, db.Close())
		}
	})
	for name, hash := range map[string]common.Hash{
		"header": rawdb.ReadHeadHeaderHash(db), "block": rawdb.ReadHeadBlockHash(db),
		"fast": rawdb.ReadHeadFastBlockHash(db), "genesis": rawdb.ReadCanonicalHash(db, 0),
	} {
		if hash != (common.Hash{}) {
			t.Fatalf("state-only artifact unexpectedly contains %s chain metadata", name)
		}
	}
	lastProgress := time.Now()
	result, err := inspectState(db, expectedHead.Root, func(current stateInspection) {
		if time.Since(lastProgress) >= 20*time.Second {
			t.Logf("export verification progress: %+v", current)
			lastProgress = time.Now()
		}
	})
	t.Logf("export verification result: %+v root=%s error=%v", result, expectedHead.Root.Hex(), err)
	requireNoError(t, err)
	if result != (stateInspection{Accounts: 801355, StorageLeaves: 2886305, CodeReferences: 33437, CodeBytes: 262368983}) {
		t.Fatal("export inventory differs from the independently traversed preserved state")
	}
	statedb, err := state.New(expectedHead.Root, expectedHead.MixDigest, state.NewDatabase(db))
	requireNoError(t, err)
	tickets, err := statedb.AllTickets()
	requireNoError(t, err)
	if !reflect.DeepEqual(tickets.ToMap(), expectedTickets) {
		t.Fatal("exported tickets differ from saved gateway observations")
	}
	requireNoError(t, state.AddCachedTickets(expectedHead.MixDigest, tickets))
	requireNoError(t, statedb.Error())
	t.Logf("matched exported tickets: commitment=%s tickets=%d owners=%d", expectedHead.MixDigest.Hex(), tickets.NumberOfTickets(), len(tickets))
	requireNoError(t, db.Close())
	closed = true
	requireNoError(t, writeStateExportJSON(filepath.Join(directory, "verified.json"), result))
	t.Log("closed export verified; this artifact contains state, not a complete chain database")
}

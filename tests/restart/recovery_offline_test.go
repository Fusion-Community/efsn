package restart

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/common/hexutil"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/core/vm"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/internal/recovery"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

type offlineRecoveryStep struct {
	Plan      recovery.Plan
	Purchase  hexutil.Bytes
	Unsigned  hexutil.Bytes
	Expected  hexutil.Bytes
	Ledger    fullStateBlockLedger
	FullState bool `json:",omitempty"`
}

func TestOfflineRecoveryProcessCuts(t *testing.T) {
	for _, cut := range []string{"completion", "export", "import"} {
		t.Run(cut, func(t *testing.T) {
			directory := prepareOfflineRecovery(t)
			for stage := 1; stage <= 3; stage++ {
				before := offlineDatabaseFiles(t, filepath.Join(directory, "working"))
				runOfflineRecoveryChild(t, directory, stage, "sign", cut)
				if cut != "import" && !reflect.DeepEqual(before, offlineDatabaseFiles(t, filepath.Join(directory, "working"))) {
					t.Fatal("offline signing/export changed chain files")
				}
				runOfflineRecoveryChild(t, directory, stage, "recover", cut)
				runOfflineRecoveryChild(t, directory, stage, "verify", cut)
				t.Logf("stage=%d kill-after=%s: exact export recovered, one callback, independent import and cold ledger agree", stage, cut)
			}
		})
	}
}

func prepareOfflineRecovery(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	original, successor := newHandoverFixture(t, "12020102000000000000000")
	for _, name := range []string{"working", "verifier"} {
		db, err := rawdb.NewLevelDBDatabase(filepath.Join(directory, name), 16, 16, "offline-fixture", false)
		requireNoError(t, err)
		batch := db.NewBatch()
		iterator := original.db.NewIterator(nil, nil)
		for iterator.Next() {
			requireNoError(t, batch.Put(iterator.Key(), iterator.Value()))
		}
		requireNoError(t, iterator.Error())
		iterator.Release()
		if batch.ValueSize() > 4<<20 {
			t.Fatal("offline fixture unexpectedly exceeds four MiB")
		}
		requireNoError(t, batch.Write())
		requireNoError(t, db.Close())
	}
	writeOfflineRecoverySteps(t, directory, original, successor, false)
	initializeOfflineJournals(t, directory)
	return directory
}

func writeOfflineRecoverySteps(t *testing.T, directory string, original, successor *fixture, fullState bool) {
	t.Helper()
	for stage := 1; stage <= 3; stage++ {
		parent := original.chain.CurrentBlock()
		signer, timestamp, next := original, parent.Time()+120, jumpTime
		if stage > 1 {
			signer, timestamp, next = successor, jumpTime+uint64(stage-2)*120, jumpTime+uint64(stage-1)*120
		}
		tx := successor.signPurchase(t, parent.Time(), ticketEnd)
		plan := recoveryPlan(t, signer, successor, timestamp, next, tx)
		candidate, err := recovery.Build(original.chain, plan, types.Transactions{tx})
		requireNoError(t, err)
		unsigned, err := rlp.EncodeToBytes(candidate.Block)
		requireNoError(t, err)
		purchase, err := rlp.EncodeToBytes(tx)
		requireNoError(t, err)
		independent := signer.buildBlockWithTransactions(t, timestamp, []*types.Transaction{tx})
		expected, err := rlp.EncodeToBytes(independent)
		requireNoError(t, err)
		original.importBlock(t, independent)
		ledger := captureFullStateBlock(t, original, parent.Root(), independent)
		requireNoError(t, writeStateExportJSON(filepath.Join(directory, fmt.Sprintf("step-%d.json", stage)), offlineRecoveryStep{Plan: plan, Purchase: purchase, Unsigned: unsigned, Expected: expected, Ledger: ledger, FullState: fullState}))
	}
}

func initializeOfflineJournals(t *testing.T, directory string) {
	t.Helper()
	for stage := 1; stage <= 2; stage++ {
		var step offlineRecoveryStep
		readHandoverJSON(t, filepath.Join(directory, fmt.Sprintf("step-%d.json", stage)), &step)
		identity := recovery.SigningIdentity{GenesisHash: step.Plan.GenesisHash, ChainID: step.Plan.ChainID, Signer: step.Plan.Signer}
		journal, err := recovery.CreateSigningJournal(filepath.Join(directory, step.Plan.Signer.Hex()), identity)
		requireNoError(t, err)
		requireNoError(t, journal.Close())
	}
}

func runOfflineRecoveryChild(t *testing.T, directory string, stage int, action, cut string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestOfflineRecoveryChild$", "-test.v", "-test.timeout=45s")
	command.Env = append(os.Environ(), "FUSION_OFFLINE_TEST_DIR="+directory, "FUSION_OFFLINE_TEST_STAGE="+strconv.Itoa(stage), "FUSION_OFFLINE_TEST_ACTION="+action, "FUSION_OFFLINE_TEST_CUT="+cut)
	if action != "sign" {
		output, err := command.CombinedOutput()
		if err != nil || bytes.Contains(output, []byte("WARNING: DATA RACE")) {
			t.Fatalf("offline %s failed: %v\n%s", action, err, output)
		}
		return
	}
	stdout, err := command.StdoutPipe()
	requireNoError(t, err)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	requireNoError(t, command.Start())
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "OFFLINE-CUT" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	var reached bool
	select {
	case reached = <-ready:
	case <-time.After(30 * time.Second):
	}
	killErr := command.Process.Kill()
	waitErr := command.Wait()
	if !reached || killErr != nil || waitErr == nil || strings.Contains(stderr.String(), "WARNING: DATA RACE") {
		t.Fatalf("child did not reach forced cut %s: kill=%v wait=%v\n%s", cut, killErr, waitErr, stderr.String())
	}
}

func TestOfflineRecoveryChild(t *testing.T) {
	directory := os.Getenv("FUSION_OFFLINE_TEST_DIR")
	if directory == "" {
		t.Skip("subprocess helper using small synthetic databases")
	}
	stage, err := strconv.Atoi(os.Getenv("FUSION_OFFLINE_TEST_STAGE"))
	requireNoError(t, err)
	var step offlineRecoveryStep
	readHandoverJSON(t, filepath.Join(directory, fmt.Sprintf("step-%d.json", stage)), &step)
	var tx types.Transaction
	requireNoError(t, rlp.DecodeBytes(step.Purchase, &tx))
	identity := recovery.SigningIdentity{GenesisHash: step.Plan.GenesisHash, ChainID: step.Plan.ChainID, Signer: step.Plan.Signer}
	journalPath := offlineJournalPath(directory, step.Plan.Signer.Hex())
	chainPath := offlineChainPath(t, directory, "working", step.FullState)
	output := filepath.Join(directory, fmt.Sprintf("export-%d.rlp", stage))
	cut := os.Getenv("FUSION_OFFLINE_TEST_CUT")
	action := os.Getenv("FUSION_OFFLINE_TEST_ACTION")
	if action == "verify" {
		verifyOfflineImport(t, chainPath, &step, step.Expected, false, nil)
		verifyOfflineImport(t, offlineChainPath(t, directory, "verifier", step.FullState), &step, step.Expected, false, nil)
		return
	}
	if action == "sign" {
		key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", 2))
		requireNoError(t, err)
		if stage == 1 {
			key, err = crypto.HexToECDSA(fmt.Sprintf("%064x", 1))
			requireNoError(t, err)
		}
		if crypto.PubkeyToAddress(key.PublicKey) != step.Plan.Signer {
			t.Fatal("test accepts only the two public synthetic signers")
		}
		sealed, err := signOfflineStep(t, directory, chainPath, journalPath, step, func(account accounts.Account, mime string, payload []byte) ([]byte, error) {
			if account.Address != identity.Signer || mime != "" {
				t.Fatal("wrong signer callback identity")
			}
			if writer, err := rawdb.NewLevelDBDatabase(chainPath, 16, 16, "", false); err == nil {
				writer.Close()
				t.Fatal("offline chain lock did not exclude concurrent writer")
			}
			if cut == "reservation" {
				offlineRecoveryCut()
			}
			marker := filepath.Join(directory, fmt.Sprintf("callback-%d", stage))
			file, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			requireNoError(t, err)
			_, err = file.WriteString("one synthetic signing callback\n")
			requireNoError(t, err)
			requireNoError(t, file.Sync())
			requireNoError(t, file.Close())
			signature, err := crypto.Sign(crypto.Keccak256(payload), key)
			if cut == "signature" {
				offlineRecoveryCut()
			}
			return signature, err
		})
		requireNoError(t, err)
		encoded, err := rlp.EncodeToBytes(sealed)
		requireNoError(t, err)
		if !bytes.Equal(encoded, step.Expected) {
			t.Fatal("offline artifact differs from independent builder")
		}
		if cut == "completion" {
			offlineRecoveryCut()
		}
		requireNoError(t, recovery.ExportSavedBlock(journalPath, identity, step.Plan.ParentHash, output))
		if cut == "export" {
			offlineRecoveryCut()
		}
		verifyOfflineImport(t, chainPath, &step, encoded, true, offlineRecoveryCut)
	}
	if action != "recover" {
		t.Fatal("unknown offline child action")
	}
	calls := 0
	sealed, err := signOfflineStep(t, directory, chainPath, journalPath, step, func(accounts.Account, string, []byte) ([]byte, error) {
		calls++
		return nil, errors.New("recovery must never invoke signer")
	})
	if cut == "import" {
		requireErrorContains(t, err, "current parent")
	} else {
		requireNoError(t, err)
		encoded, err := rlp.EncodeToBytes(sealed)
		requireNoError(t, err)
		if !bytes.Equal(encoded, step.Expected) {
			t.Fatal("retry changed completed artifact")
		}
	}
	if calls != 0 {
		t.Fatal("recovery invoked signer again")
	}
	marker, err := os.ReadFile(filepath.Join(directory, fmt.Sprintf("callback-%d", stage)))
	requireNoError(t, err)
	if string(marker) != "one synthetic signing callback\n" {
		t.Fatal("missing original callback record")
	}
	if cut != "completion" {
		previous, err := os.ReadFile(output)
		requireNoError(t, err)
		if !bytes.Equal(previous, step.Expected) {
			t.Fatal("original export differs after interruption")
		}
	}
	output = filepath.Join(directory, fmt.Sprintf("recovered-%d.rlp", stage))
	requireNoError(t, recovery.ExportSavedBlock(journalPath, identity, step.Plan.ParentHash, output))
	encoded, err := os.ReadFile(output)
	requireNoError(t, err)
	if !bytes.Equal(encoded, step.Expected) {
		t.Fatal("recovered export changed signature or block")
	}
	verifyOfflineImport(t, chainPath, &step, encoded, true, nil)
	verifyOfflineImport(t, offlineChainPath(t, directory, "verifier", step.FullState), &step, encoded, true, nil)
}

func offlineChainPath(t *testing.T, directory, role string, fullState bool) string {
	t.Helper()
	path := filepath.Join(directory, role)
	if fullState {
		requireFullStateCopy(t, path)
		path = filepath.Join(path, "chaindata")
	}
	return path
}

func offlineRecoveryCut() {
	fmt.Fprintln(os.Stdout, "OFFLINE-CUT")
	select {}
}

func verifyOfflineImport(t *testing.T, path string, step *offlineRecoveryStep, encoded []byte, allowImport bool, afterImport func()) {
	t.Helper()
	var block types.Block
	requireNoError(t, rlp.DecodeBytes(encoded, &block))
	if !bytes.Equal(encoded, step.Expected) {
		t.Fatal("unreviewed import artifact")
	}
	db, err := rawdb.NewLevelDBDatabase(path, 16, 16, "offline-import", false)
	requireNoError(t, err)
	defer db.Close()
	reader, err := recovery.NewReader(db)
	requireNoError(t, err)
	head := reader.CurrentHeader().Hash()
	if head != step.Plan.ParentHash && head != block.Hash() {
		t.Fatal("unexpected persisted head before import/startup")
	}
	engine := datong.New(reader.Config().DaTong, db)
	chain, err := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, reader.Config(), engine, vm.Config{}, nil)
	requireNoError(t, err)
	defer chain.Stop()
	if chain.CurrentBlock().Hash() != head {
		t.Fatal("startup repaired the offline handover head")
	}
	if head == step.Plan.ParentHash {
		if !allowImport {
			t.Fatal("cold verification lost imported block")
		}
		_, err := chain.InsertChain(types.Blocks{&block})
		requireNoError(t, err)
	}
	if chain.CurrentBlock().Hash() != block.Hash() || chain.CurrentHeader().Hash() != block.Hash() || chain.CurrentFastBlock().Hash() != block.Hash() {
		t.Fatal("imported heads differ")
	}
	parent := chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		t.Fatal("missing imported parent")
	}
	f := &fixture{db: db, chain: chain, engine: engine}
	if step.FullState {
		verifyFullStateContextReads(t, f, block.Header())
	}
	actual, err := json.Marshal(captureFullStateBlock(t, f, parent.Root, &block))
	requireNoError(t, err)
	want, err := json.Marshal(step.Ledger)
	requireNoError(t, err)
	if !bytes.Equal(actual, want) {
		t.Fatal("cold accounts, receipts, tickets or header differ from independent ledger")
	}
	if afterImport != nil {
		afterImport()
	}
}

func offlineDatabaseFiles(t *testing.T, path string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(path)
	requireNoError(t, err)
	result := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatal("unexpected directory in small offline fixture")
		}
		result[entry.Name()] = stateExportFileHash(t, filepath.Join(path, entry.Name()))
	}
	return result
}

func TestOfflineRecoveryUncertainCuts(t *testing.T) {
	for _, cut := range []string{"reservation", "signature"} {
		t.Run(cut, func(t *testing.T) {
			requireOfflineUncertain(t, prepareOfflineRecovery(t), cut)
		})
	}
}

func requireOfflineUncertain(t *testing.T, directory, cut string) {
	t.Helper()
	var step offlineRecoveryStep
	readHandoverJSON(t, filepath.Join(directory, "step-1.json"), &step)
	chainPath := offlineChainPath(t, directory, "working", step.FullState)
	before := offlineDatabaseFiles(t, chainPath)
	runOfflineRecoveryChild(t, directory, 1, "sign", cut)
	var tx types.Transaction
	requireNoError(t, rlp.DecodeBytes(step.Purchase, &tx))
	calls := 0
	path := offlineJournalPath(directory, step.Plan.Signer.Hex())
	_, err := signOfflineStep(t, directory, chainPath, path, step, func(accounts.Account, string, []byte) ([]byte, error) {
		calls++
		return nil, errors.New("unexpected callback")
	})
	if !errors.Is(err, recovery.ErrSigningUncertain) || calls != 0 {
		t.Fatalf("uncertain attempt retried: calls=%d error=%v", calls, err)
	}
	identity := recovery.SigningIdentity{GenesisHash: step.Plan.GenesisHash, ChainID: step.Plan.ChainID, Signer: step.Plan.Signer}
	output := filepath.Join(directory, "refused.rlp")
	err = recovery.ExportSavedBlock(path, identity, step.Plan.ParentHash, output)
	if !errors.Is(err, recovery.ErrSigningUncertain) {
		t.Fatalf("uncertain attempt exported: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) || !reflect.DeepEqual(before, offlineDatabaseFiles(t, chainPath)) {
		t.Fatal("uncertain recovery exported or changed chain files")
	}
	t.Logf("kill-after=%s: repeat signing and export refused; chain bytes unchanged", cut)
}

func TestOfflineRecoveryRefusals(t *testing.T) {
	directory := prepareOfflineRecovery(t)
	var step offlineRecoveryStep
	readHandoverJSON(t, filepath.Join(directory, "step-1.json"), &step)
	var tx types.Transaction
	requireNoError(t, rlp.DecodeBytes(step.Purchase, &tx))
	chainPath := filepath.Join(directory, "working")
	journalPath := filepath.Join(directory, step.Plan.Signer.Hex())
	before := offlineDatabaseFiles(t, chainPath)
	calls := 0
	callback := func(accounts.Account, string, []byte) ([]byte, error) {
		calls++
		return nil, errors.New("refused input reached signer")
	}
	for _, test := range []struct {
		name, chain, journal, message string
	}{
		{"relative_chain", "working", journalPath, "absolute"},
		{"relative_journal", chainPath, "journal", "absolute"},
		{"missing_chain", filepath.Join(directory, "missing-chain"), journalPath, ""},
		{"missing_journal", chainPath, filepath.Join(directory, "missing-journal"), ""},
		{"same_directory", chainPath, chainPath, "separate"},
		{"journal_contains_chain", chainPath, directory, "separate"},
		{"chain_contains_journal", directory, journalPath, "separate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := recovery.SignOffline(test.chain, test.journal, step.Plan, types.Transactions{&tx}, step.Unsigned, callback)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("expected refusal %q, got %v", test.message, err)
			}
		})
	}
	for _, path := range []string{"missing-chain", "missing-journal"} {
		if _, err := os.Stat(filepath.Join(directory, path)); !os.IsNotExist(err) {
			t.Fatal("missing path was created")
		}
	}
	if !reflect.DeepEqual(before, offlineDatabaseFiles(t, chainPath)) {
		t.Fatal("path refusals changed chain files")
	}
	writer, err := rawdb.NewLevelDBDatabase(chainPath, 16, 16, "offline-writer-test", false)
	requireNoError(t, err)
	_, err = recovery.SignOffline(chainPath, journalPath, step.Plan, types.Transactions{&tx}, step.Unsigned, callback)
	if err == nil {
		t.Fatal("active chain writer accepted")
	}
	requireNoError(t, writer.Close())
	before = offlineDatabaseFiles(t, chainPath)
	for _, mode := range []string{"unsigned", "purchase", "identity", "horizon", "parent"} {
		plan, reviewed, txs := step.Plan, step.Unsigned, types.Transactions{&tx}
		switch mode {
		case "unsigned":
			reviewed = append(append([]byte{}, reviewed...), 0)
		case "purchase":
			txs = nil
		case "identity":
			plan.ChainID++
		case "horizon":
			plan.NextTimestamp = plan.Purchase.End
		case "parent":
			plan.ParentNumber++
		}
		if _, err := recovery.SignOffline(chainPath, journalPath, plan, txs, reviewed, callback); err == nil {
			t.Fatalf("changed %s accepted", mode)
		}
	}
	identity := recovery.SigningIdentity{GenesisHash: step.Plan.GenesisHash, ChainID: step.Plan.ChainID, Signer: step.Plan.Signer}
	journal, err := recovery.OpenSigningJournal(journalPath, identity)
	requireNoError(t, err)
	_, err = recovery.SignOffline(chainPath, journalPath, step.Plan, types.Transactions{&tx}, step.Unsigned, callback)
	if err == nil {
		t.Fatal("active journal writer accepted")
	}
	if _, err := journal.Saved(step.Plan.ParentHash); err == nil || errors.Is(err, recovery.ErrSigningUncertain) {
		t.Fatalf("refused requests left a signing reservation: %v", err)
	}
	requireNoError(t, journal.Close())
	if calls != 0 || !reflect.DeepEqual(before, offlineDatabaseFiles(t, chainPath)) {
		t.Fatal("refused requests signed or changed chain files")
	}
	runOfflineRecoveryChild(t, directory, 1, "sign", "completion")
	db, err := rawdb.NewLevelDBDatabase(chainPath, 16, 16, "", true)
	requireNoError(t, err)
	reader, err := recovery.NewReader(db)
	requireNoError(t, err)
	conflict := step.Plan
	conflict.Timestamp += 7
	candidate, err := recovery.Build(reader, conflict, types.Transactions{&tx})
	requireNoError(t, err)
	reviewed, err := rlp.EncodeToBytes(candidate.Block)
	requireNoError(t, err)
	requireNoError(t, db.Close())
	_, err = recovery.SignOffline(chainPath, journalPath, conflict, types.Transactions{&tx}, reviewed, callback)
	if !errors.Is(err, recovery.ErrSigningConflict) || calls != 0 {
		t.Fatalf("conflicting offline signature permitted: calls=%d error=%v", calls, err)
	}
	writer, err = rawdb.NewLevelDBDatabase(chainPath, 16, 16, "", false)
	requireNoError(t, err)
	rawdb.WriteHeadFastBlockHash(writer, step.Plan.GenesisHash)
	requireNoError(t, writer.Close())
	before = offlineDatabaseFiles(t, chainPath)
	_, err = recovery.SignOffline(chainPath, journalPath, step.Plan, types.Transactions{&tx}, step.Unsigned, callback)
	requireErrorContains(t, err, "heads must agree")
	if calls != 0 || !reflect.DeepEqual(before, offlineDatabaseFiles(t, chainPath)) {
		t.Fatal("inconsistent-head refusal signed or repaired chain data")
	}
	t.Log("active chain/journal locks, missing/overlapping paths, changed inputs and conflicting candidate refused before signer")
}

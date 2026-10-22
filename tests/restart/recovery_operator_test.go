package restart

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/accounts/keystore"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/common/hexutil"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/internal/recovery"
	"github.com/syndtr/goleveldb/leveldb"
)

func runRecoveryOperator(t *testing.T, password string, success bool, args ...string) []byte {
	t.Helper()
	binary := os.Getenv("FUSION_RECOVERY_OPERATOR")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdin = strings.NewReader(password)
	output, err := command.CombinedOutput()
	if (err == nil) != success || bytes.Contains(output, []byte("WARNING: DATA RACE")) || bytes.Contains(output, []byte("public operator password")) {
		t.Fatalf("operator success=%t err=%v output=%s", success, err, output)
	}
	return output
}

func TestKeystorePreflightLocksAndUncertain(t *testing.T) {
	t.Setenv("FUSION_OFFLINE_TEST_APPROVED", "1")
	directory := prepareOfflineRecovery(t)
	prepareApprovedOffline(t, directory)
	var step offlineRecoveryStep
	readHandoverJSON(t, filepath.Join(directory, "step-1.json"), &step)
	var policy recovery.SigningPolicy
	readHandoverJSON(t, filepath.Join(directory, "policy-"+step.Plan.Signer.Hex()+".json"), &policy)
	approval, err := recovery.EncodeSigningApproval(recovery.SigningApproval{Version: 1, Policy: policy, Plan: step.Plan, Purchase: step.Purchase, UnsignedBlock: step.Unsigned})
	requireNoError(t, err)
	digest := common.Hash(sha256.Sum256(approval))
	key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", 1))
	requireNoError(t, err)
	keyData, err := keystore.EncryptKey(&keystore.Key{PrivateKey: key, Address: step.Plan.Signer}, "public test password", 2, 1)
	requireNoError(t, err)
	keyPath := filepath.Join(directory, "key.json")
	requireNoError(t, os.WriteFile(keyPath, keyData, 0600))
	chainPath := filepath.Join(directory, "working")
	journalPath := offlineJournalPath(directory, step.Plan.Signer.Hex())
	identity := recovery.SigningIdentity{GenesisHash: step.Plan.GenesisHash, ChainID: step.Plan.ChainID, Signer: step.Plan.Signer}
	calls := 0
	_, err = recovery.SignApprovedKeystore(chainPath, journalPath, approval, digest, keyPath, func() ([]byte, error) {
		calls++
		if writer, err := rawdb.NewLevelDBDatabase(chainPath, 16, 16, "", false); err == nil {
			writer.Close()
			t.Fatal("credential preflight released chain lock")
		}
		if writer, err := recovery.OpenSigningJournal(journalPath, identity); err == nil {
			writer.Close()
			t.Fatal("credential preflight released journal lock")
		}
		return []byte("wrong public test password"), nil
	})
	if err == nil || errors.Is(err, recovery.ErrSigningUncertain) || calls != 1 {
		t.Fatalf("unexpected preflight: calls=%d error=%v", calls, err)
	}
	_, err = recovery.SignApprovedOffline(chainPath, journalPath, approval, digest, func(accounts.Account, string, []byte) ([]byte, error) {
		return nil, errors.New("ambiguous signature failure")
	})
	if !errors.Is(err, recovery.ErrSigningUncertain) {
		t.Fatal(err)
	}
	_, err = recovery.SignApprovedKeystore(chainPath, journalPath, approval, digest, filepath.Join(directory, "missing.json"), func() ([]byte, error) {
		t.Fatal("unfinished signature reopened credentials")
		return nil, nil
	})
	if !errors.Is(err, recovery.ErrSigningUncertain) {
		t.Fatalf("unfinished attempt was not refused before key access: %v", err)
	}
	t.Log("credential validation holds both locks; wrong password permits a later attempt; unfinished signature refuses key access")
}

func TestRecoveryOperatorCLI(t *testing.T) {
	if !filepath.IsAbs(os.Getenv("FUSION_RECOVERY_OPERATOR")) {
		t.Skip("requires separately built recovery executable")
	}
	directory := prepareOfflineRecovery(t)
	runRecoveryOperatorStages(t, directory, false)
}

func runRecoveryOperatorStages(t *testing.T, directory string, fullState bool) {
	t.Helper()
	working := offlineChainPath(t, directory, "working", fullState)
	var firstDonation string
	var firstDonationDigest string
	for stage := 1; stage <= 3; stage++ {
		var step offlineRecoveryStep
		readHandoverJSON(t, filepath.Join(directory, fmt.Sprintf("step-%d.json", stage)), &step)
		prefix := filepath.Join(directory, fmt.Sprintf("operator-%d", stage))
		requireNoError(t, writeStateExportJSON(prefix+"-plan.json", step.Plan))
		requireNoError(t, os.WriteFile(prefix+"-purchase.rlp", step.Purchase, 0600))
		before := offlineDatabaseFiles(t, working)
		runRecoveryOperator(t, "", true, "review", "-chaindata", working, "-plan", prefix+"-plan.json", "-purchase", prefix+"-purchase.rlp", "-out", prefix+"-report.json")
		var report struct{ UnsignedBlock hexutil.Bytes }
		data, err := os.ReadFile(prefix + "-report.json")
		requireNoError(t, err)
		requireNoError(t, json.Unmarshal(data, &report))
		if !bytes.Equal(report.UnsignedBlock, step.Unsigned) {
			t.Fatal("command report differs from independent fixture")
		}
		prepare := []string{"prepare", "-chaindata", working, "-report", prefix + "-report.json", "-purchase", prefix + "-purchase.rlp", "-out", prefix + "-approval.json"}
		if stage <= 2 {
			prepare = append(prepare, "-blocks", fmt.Sprint(stage))
		} else {
			prepare = append(prepare, "-policy-from", firstDonation, "-policy-sha256", firstDonationDigest)
		}
		if stage == 1 {
			var altered map[string]json.RawMessage
			requireNoError(t, json.Unmarshal(data, &altered))
			changed := bytes.Replace(data, []byte(`"Selected": `+string(altered["Selected"])), []byte(`"Selected": "0x0000000000000000000000000000000000000000000000000000000000000000"`), 1)
			if bytes.Equal(data, changed) {
				t.Fatal("report mutation did not change selected ticket")
			}
			requireNoError(t, os.WriteFile(prefix+"-report.json", changed, 0600))
			runRecoveryOperator(t, "", false, prepare...)
			if _, err := os.Stat(prefix + "-approval.json"); !os.IsNotExist(err) {
				t.Fatal("changed human report produced an approval")
			}
			requireNoError(t, os.WriteFile(prefix+"-report.json", data, 0600))
		}
		runRecoveryOperator(t, "", true, prepare...)
		approval, err := os.ReadFile(prefix + "-approval.json")
		requireNoError(t, err)
		digest := fmt.Sprintf("%x", sha256.Sum256(approval))
		if stage == 2 {
			firstDonation, firstDonationDigest = prefix+"-approval.json", digest
		}
		journal := filepath.Join(directory, "operator-journal-"+step.Plan.Signer.Hex())
		commonArgs := []string{"-approval", prefix + "-approval.json", "-approved-sha256", digest, "-journal", journal}
		if stage <= 2 {
			args := append([]string{"init-journal", "-chaindata", working}, commonArgs...)
			runRecoveryOperator(t, "", true, args...)
			runRecoveryOperator(t, "", false, args...)
		}
		scalar := 2
		if stage == 1 {
			scalar = 1
		}
		key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", scalar))
		requireNoError(t, err)
		keyData, err := keystore.EncryptKey(&keystore.Key{PrivateKey: key, Address: crypto.PubkeyToAddress(key.PublicKey)}, "public operator password", 2, 1)
		requireNoError(t, err)
		keyPath := prefix + "-encrypted-key.json"
		requireNoError(t, os.WriteFile(keyPath, keyData, 0600))
		signArgs := append([]string{"sign", "-chaindata", working, "-keyfile", keyPath, "-password-stdin"}, commonArgs...)
		runRecoveryOperator(t, "wrong public operator password\n", false, signArgs...)
		identity := recovery.SigningIdentity{GenesisHash: step.Plan.GenesisHash, ChainID: step.Plan.ChainID, Signer: step.Plan.Signer}
		saved, err := recovery.OpenSigningJournal(journal, identity)
		requireNoError(t, err)
		_, err = saved.Saved(step.Plan.ParentHash)
		if err != leveldb.ErrNotFound {
			t.Fatalf("wrong password consumed stage %d reservation: %v", stage, err)
		}
		requireNoError(t, saved.Close())
		runRecoveryOperator(t, "public operator password\n", true, signArgs...)
		repeat := append([]string{"sign", "-chaindata", working, "-keyfile", prefix + "-missing-key.json", "-password-stdin"}, commonArgs...)
		runRecoveryOperator(t, "", true, repeat...)
		exportArgs := append([]string{"export", "-out", prefix + "-block.rlp"}, commonArgs...)
		runRecoveryOperator(t, "", true, exportArgs...)
		runRecoveryOperator(t, "", false, exportArgs...)
		encoded, err := os.ReadFile(prefix + "-block.rlp")
		requireNoError(t, err)
		if !bytes.Equal(encoded, step.Expected) {
			t.Fatal("operator block differs from independent builder")
		}
		if !reflect.DeepEqual(before, offlineDatabaseFiles(t, working)) {
			t.Fatal("operator workflow changed stopped chain files")
		}
		for _, role := range []string{"working", "verifier"} {
			runRecoveryOperatorImport(t, directory, stage, role, "import")
			runRecoveryOperatorImport(t, directory, stage, role, "cold")
		}
		runRecoveryOperator(t, "", true, append([]string{"export", "-out", prefix + "-after-import.rlp"}, commonArgs...)...)
		altered, err := recovery.DecodeSigningApproval(approval, common.Hash(sha256.Sum256(approval)))
		requireNoError(t, err)
		altered.UnsignedBlock = []byte{0}
		changed, err := recovery.EncodeSigningApproval(*altered)
		requireNoError(t, err)
		if err := recovery.ExportApprovedBlock(journal, changed, common.Hash(sha256.Sum256(changed)), prefix+"-refused.rlp"); err == nil {
			t.Fatal("export accepted different reviewed block")
		}
		if _, err := os.Stat(prefix + "-refused.rlp"); !os.IsNotExist(err) {
			t.Fatal("refused export created a file")
		}
		t.Logf("stage=%d: actual review/prepare/init/sign/export commands; wrong password leaves no reservation; repeat needs no key; exact independent block and cold ledgers agree", stage)
	}
}

func runRecoveryOperatorImport(t *testing.T, directory string, stage int, role, action string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRecoveryOperatorImportChild$", "-test.v", "-test.timeout=80s")
	command.Env = append(os.Environ(), "FUSION_OPERATOR_IMPORT_DIR="+directory, fmt.Sprintf("FUSION_OPERATOR_IMPORT_STAGE=%d", stage), "FUSION_OPERATOR_IMPORT_ROLE="+role, "FUSION_OPERATOR_IMPORT_ACTION="+action)
	output, err := command.CombinedOutput()
	if err != nil || bytes.Contains(output, []byte("WARNING: DATA RACE")) || !bytes.Contains(output, []byte("OPERATOR-IMPORT-VERIFIED")) {
		t.Fatalf("operator %s %s failed: %v\n%s", role, action, err, output)
	}
}

func TestRecoveryOperatorImportChild(t *testing.T) {
	directory := os.Getenv("FUSION_OPERATOR_IMPORT_DIR")
	if directory == "" {
		t.Skip("subprocess helper for disposable operator fixtures")
	}
	role, action := os.Getenv("FUSION_OPERATOR_IMPORT_ROLE"), os.Getenv("FUSION_OPERATOR_IMPORT_ACTION")
	stage := os.Getenv("FUSION_OPERATOR_IMPORT_STAGE")
	if !filepath.IsAbs(directory) || (role != "working" && role != "verifier") || (action != "import" && action != "cold") || (stage != "1" && stage != "2" && stage != "3") || os.Getenv("FUSION_RESTART_CHAINDATA") != "" {
		t.Fatal("invalid disposable import settings")
	}
	var step offlineRecoveryStep
	readHandoverJSON(t, filepath.Join(directory, "step-"+stage+".json"), &step)
	encoded, err := os.ReadFile(filepath.Join(directory, "operator-"+stage+"-block.rlp"))
	requireNoError(t, err)
	verifyOfflineImport(t, offlineChainPath(t, directory, role, step.FullState), &step, encoded, action == "import", nil)
	fmt.Println("OPERATOR-IMPORT-VERIFIED")
}

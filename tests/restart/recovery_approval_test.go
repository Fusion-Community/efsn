package restart

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/internal/recovery"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

func offlineJournalPath(directory, signer string) string {
	if os.Getenv("FUSION_OFFLINE_TEST_APPROVED") == "1" {
		return filepath.Join(directory, "approved", signer)
	}
	return filepath.Join(directory, signer)
}

func signOfflineStep(t *testing.T, directory, chainPath, journalPath string, step offlineRecoveryStep, signer datong.SignerFn) (*types.Block, error) {
	t.Helper()
	if os.Getenv("FUSION_OFFLINE_TEST_APPROVED") == "1" {
		var policy recovery.SigningPolicy
		readHandoverJSON(t, filepath.Join(directory, "policy-"+step.Plan.Signer.Hex()+".json"), &policy)
		approval := recovery.SigningApproval{Version: 1, Policy: policy, Plan: step.Plan, Purchase: step.Purchase, UnsignedBlock: step.Unsigned}
		encoded, err := recovery.EncodeSigningApproval(approval)
		requireNoError(t, err)
		return recovery.SignApprovedOffline(chainPath, journalPath, encoded, common.Hash(sha256.Sum256(encoded)), signer)
	}
	var tx types.Transaction
	requireNoError(t, rlp.DecodeBytes(step.Purchase, &tx))
	return recovery.SignOffline(chainPath, journalPath, step.Plan, types.Transactions{&tx}, step.Unsigned, signer)
}

func prepareApprovedOffline(t *testing.T, directory string) {
	t.Helper()
	db, err := rawdb.NewLevelDBDatabase(filepath.Join(directory, "working"), 16, 16, "approval-fixture", true)
	requireNoError(t, err)
	reader, err := recovery.NewReader(db)
	requireNoError(t, err)
	config, err := recovery.ConfigurationSHA256(reader.Config())
	requireNoError(t, err)
	requireNoError(t, db.Close())
	executable, err := recovery.ExecutableSHA256()
	requireNoError(t, err)
	for stage := 1; stage <= 2; stage++ {
		var step offlineRecoveryStep
		readHandoverJSON(t, filepath.Join(directory, fmt.Sprintf("step-%d.json", stage)), &step)
		policy := recovery.SigningPolicy{FirstParent: step.Plan.ParentHash, FirstParentNumber: step.Plan.ParentNumber, PurchaseOwner: step.Plan.Purchase.Owner, BlockCount: uint64(stage), ExecutableSHA256: executable, ConfigSHA256: config}
		journal, err := recovery.CreateApprovedSigningJournal(offlineJournalPath(directory, step.Plan.Signer.Hex()), recovery.SigningIdentity{GenesisHash: step.Plan.GenesisHash, ChainID: step.Plan.ChainID, Signer: step.Plan.Signer}, policy)
		requireNoError(t, err)
		requireNoError(t, journal.Close())
		requireNoError(t, writeStateExportJSON(filepath.Join(directory, "policy-"+step.Plan.Signer.Hex()+".json"), policy))
	}
}

func TestApprovedOfflineProcessCuts(t *testing.T) {
	t.Setenv("FUSION_OFFLINE_TEST_APPROVED", "1")
	for _, cut := range []string{"completion", "export", "import", "reservation", "signature"} {
		t.Run(cut, func(t *testing.T) {
			directory := prepareOfflineRecovery(t)
			prepareApprovedOffline(t, directory)
			if cut == "reservation" || cut == "signature" {
				requireOfflineUncertain(t, directory, cut)
				return
			}
			for stage := 1; stage <= 3; stage++ {
				before := offlineDatabaseFiles(t, filepath.Join(directory, "working"))
				runOfflineRecoveryChild(t, directory, stage, "sign", cut)
				if cut != "import" && !reflect.DeepEqual(before, offlineDatabaseFiles(t, filepath.Join(directory, "working"))) {
					t.Fatal("approved signing/export changed chain files")
				}
				runOfflineRecoveryChild(t, directory, stage, "recover", cut)
				runOfflineRecoveryChild(t, directory, stage, "verify", cut)
				t.Logf("approved stage=%d cut=%s: exact recovery without another callback; independent cold ledgers agree", stage, cut)
			}
		})
	}
}

func TestApprovedOfflineRefusals(t *testing.T) {
	t.Setenv("FUSION_OFFLINE_TEST_APPROVED", "1")
	directory := prepareOfflineRecovery(t)
	prepareApprovedOffline(t, directory)
	var step offlineRecoveryStep
	readHandoverJSON(t, filepath.Join(directory, "step-1.json"), &step)
	var policy recovery.SigningPolicy
	readHandoverJSON(t, filepath.Join(directory, "policy-"+step.Plan.Signer.Hex()+".json"), &policy)
	approval := recovery.SigningApproval{Version: 1, Policy: policy, Plan: step.Plan, Purchase: step.Purchase, UnsignedBlock: step.Unsigned}
	chainPath := filepath.Join(directory, "working")
	journalPath := offlineJournalPath(directory, step.Plan.Signer.Hex())
	before := offlineDatabaseFiles(t, chainPath)
	for name, mutate := range map[string]func(*recovery.SigningApproval){
		"policy_quota":      func(a *recovery.SigningApproval) { a.Policy.BlockCount++ },
		"policy_parent":     func(a *recovery.SigningApproval) { a.Policy.FirstParent[0]++ },
		"policy_executable": func(a *recovery.SigningApproval) { a.Policy.ExecutableSHA256[0]++ },
		"policy_config":     func(a *recovery.SigningApproval) { a.Policy.ConfigSHA256[0]++ },
		"purchase_owner":    func(a *recovery.SigningApproval) { a.Plan.Purchase.Owner[0]++ },
		"parent":            func(a *recovery.SigningApproval) { a.Plan.ParentHash[0]++ },
		"purchase_bytes":    func(a *recovery.SigningApproval) { a.Purchase = []byte{0} },
		"unsigned_bytes":    func(a *recovery.SigningApproval) { a.UnsignedBlock = []byte{0} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := approval
			mutate(&changed)
			data, err := recovery.EncodeSigningApproval(changed)
			requireNoError(t, err)
			calls := 0
			_, err = recovery.SignApprovedOffline(chainPath, journalPath, data, common.Hash(sha256.Sum256(data)), func(accounts.Account, string, []byte) ([]byte, error) {
				calls++
				return nil, fmt.Errorf("unexpected signer access")
			})
			if err == nil || calls != 0 {
				t.Fatalf("changed approval reached signer: calls=%d error=%v", calls, err)
			}
		})
	}
	data, err := recovery.EncodeSigningApproval(approval)
	requireNoError(t, err)
	if _, err := recovery.SignApprovedOffline(chainPath, journalPath, data, common.Hash{}, nil); err == nil {
		t.Fatal("unreviewed digest accepted")
	}
	var tx types.Transaction
	requireNoError(t, rlp.DecodeBytes(step.Purchase, &tx))
	if _, err := recovery.SignOffline(chainPath, journalPath, step.Plan, types.Transactions{&tx}, step.Unsigned, nil); err == nil {
		t.Fatal("legacy wrapper bypassed immutable policy")
	}
	if _, err := recovery.SignApprovedOffline(chainPath, filepath.Join(directory, step.Plan.Signer.Hex()), data, common.Hash(sha256.Sum256(data)), nil); err == nil {
		t.Fatal("legacy journal accepted approved signing")
	}
	for _, mismatch := range []string{"executable", "configuration"} {
		changed := approval
		if mismatch == "executable" {
			changed.Policy.ExecutableSHA256[0]++
		} else {
			changed.Policy.ConfigSHA256[0]++
		}
		path := filepath.Join(directory, mismatch)
		journal, err := recovery.CreateApprovedSigningJournal(path, recovery.SigningIdentity{GenesisHash: step.Plan.GenesisHash, ChainID: step.Plan.ChainID, Signer: step.Plan.Signer}, changed.Policy)
		requireNoError(t, err)
		requireNoError(t, journal.Close())
		encoded, err := recovery.EncodeSigningApproval(changed)
		requireNoError(t, err)
		_, err = recovery.SignApprovedOffline(chainPath, path, encoded, common.Hash(sha256.Sum256(encoded)), nil)
		requireErrorContains(t, err, "executable or chain configuration")
	}
	if !reflect.DeepEqual(before, offlineDatabaseFiles(t, chainPath)) {
		t.Fatal("approval refusals changed chain files")
	}
}

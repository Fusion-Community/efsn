package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/common/hexutil"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/params"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

type SigningApproval struct {
	Version       uint64
	Policy        SigningPolicy
	Plan          Plan
	Purchase      hexutil.Bytes
	UnsignedBlock hexutil.Bytes
}

func EncodeSigningApproval(approval SigningApproval) ([]byte, error) {
	data, err := json.MarshalIndent(approval, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func decodeSigningApproval(data []byte, approvedSHA256 common.Hash) (*SigningApproval, error) {
	if len(data) > 1<<20 || common.Hash(sha256.Sum256(data)) != approvedSHA256 {
		return nil, fmt.Errorf("approval exceeds one MiB or differs from reviewed SHA-256")
	}
	var approval SigningApproval
	if err := json.Unmarshal(data, &approval); err != nil {
		return nil, err
	}
	canonical, err := EncodeSigningApproval(approval)
	if err != nil || !bytes.Equal(data, canonical) || approval.Version != 1 {
		return nil, fmt.Errorf("version 1 canonical signing approval required")
	}
	return &approval, nil
}

func DecodeSigningApproval(data []byte, approvedSHA256 common.Hash) (*SigningApproval, error) {
	return decodeSigningApproval(data, approvedSHA256)
}

func ExecutableSHA256() (common.Hash, error) {
	path, err := os.Executable()
	if err != nil {
		return common.Hash{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return common.Hash{}, err
	}
	defer file.Close()
	checksum := sha256.New()
	if _, err := io.Copy(checksum, file); err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(checksum.Sum(nil)), nil
}

func ConfigurationSHA256(config *params.ChainConfig) (common.Hash, error) {
	if config == nil {
		return common.Hash{}, fmt.Errorf("chain configuration required")
	}
	data, err := json.Marshal(config)
	return common.Hash(sha256.Sum256(data)), err
}

func SignApprovedOffline(chainPath, journalPath string, data []byte, approvedSHA256 common.Hash, signer datong.SignerFn) (*types.Block, error) {
	return signApprovedOffline(chainPath, journalPath, data, approvedSHA256, fixedSigner(signer))
}

func signApprovedOffline(chainPath, journalPath string, data []byte, approvedSHA256 common.Hash, open signerPreflight) (*types.Block, error) {
	approval, err := decodeSigningApproval(data, approvedSHA256)
	if err != nil {
		return nil, err
	}
	plan := approval.Plan
	identity := SigningIdentity{GenesisHash: plan.GenesisHash, ChainID: plan.ChainID, Signer: plan.Signer}
	return withOfflineJournal(chainPath, journalPath, identity, func(reader *Reader, journal *SigningJournal) (*types.Block, error) {
		journal.mu.Lock()
		defer journal.mu.Unlock()
		if journal.policy == nil || *journal.policy != approval.Policy || plan.Purchase.Owner != approval.Policy.PurchaseOwner {
			return nil, fmt.Errorf("approval differs from immutable journal policy")
		}
		if err := checkApprovalContext(reader, approval); err != nil {
			return nil, err
		}
		var purchase types.Transaction
		if err := rlp.DecodeBytes(approval.Purchase, &purchase); err != nil {
			return nil, err
		}
		return journal.signReviewedWithPreflight(reader, plan, types.Transactions{&purchase}, approval.UnsignedBlock, open)
	})
}

func checkApprovalContext(reader *Reader, approval *SigningApproval) error {
	plan := approval.Plan
	identity := SigningIdentity{GenesisHash: plan.GenesisHash, ChainID: plan.ChainID, Signer: plan.Signer}
	if err := validateSigningPolicy(identity, approval.Policy); err != nil {
		return err
	}
	if plan.Purchase.Owner != approval.Policy.PurchaseOwner {
		return fmt.Errorf("purchase owner differs from policy")
	}
	executable, err := ExecutableSHA256()
	if err != nil {
		return err
	}
	config, err := ConfigurationSHA256(reader.Config())
	if err != nil {
		return err
	}
	if executable != approval.Policy.ExecutableSHA256 || config != approval.Policy.ConfigSHA256 {
		return fmt.Errorf("executable or chain configuration differs from approved policy")
	}
	return nil
}

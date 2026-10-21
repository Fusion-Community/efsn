package recovery

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

func InitializeApprovedOffline(chainPath, journalPath string, data []byte, approvedSHA256 common.Hash) error {
	approval, err := decodeSigningApproval(data, approvedSHA256)
	if err != nil {
		return err
	}
	chainPath, err = existingDirectory(chainPath)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(journalPath) {
		return fmt.Errorf("absolute new journal path required")
	}
	parent, err := existingDirectory(filepath.Dir(journalPath))
	if err != nil {
		return err
	}
	journalPath = filepath.Join(parent, filepath.Base(journalPath))
	if _, err := os.Lstat(journalPath); err == nil {
		return fmt.Errorf("journal path already exists; initialization cannot replace it")
	} else if !os.IsNotExist(err) {
		return err
	}
	if containsPath(chainPath, journalPath) || containsPath(journalPath, chainPath) {
		return fmt.Errorf("signing journal and chain data must be separate directories")
	}
	plan := approval.Plan
	if plan.ParentHash != approval.Policy.FirstParent || plan.ParentNumber != approval.Policy.FirstParentNumber {
		return fmt.Errorf("journal initialization requires the first approved stage")
	}
	_, err = withStoppedChain(chainPath, func(reader *Reader) (*types.Block, error) {
		if err := checkApprovalContext(reader, approval); err != nil {
			return nil, err
		}
		var purchase types.Transaction
		if err := rlp.DecodeBytes(approval.Purchase, &purchase); err != nil {
			return nil, err
		}
		if _, err := reviewedCandidate(reader, plan, types.Transactions{&purchase}, approval.UnsignedBlock); err != nil {
			return nil, err
		}
		journal, err := CreateApprovedSigningJournal(journalPath, SigningIdentity{GenesisHash: plan.GenesisHash, ChainID: plan.ChainID, Signer: plan.Signer}, approval.Policy)
		if err != nil {
			return nil, err
		}
		return nil, journal.Close()
	})
	return err
}

func ExportApprovedBlock(journalPath string, data []byte, approvedSHA256 common.Hash, output string) error {
	approval, err := decodeSigningApproval(data, approvedSHA256)
	if err != nil {
		return err
	}
	plan := approval.Plan
	identity := SigningIdentity{GenesisHash: plan.GenesisHash, ChainID: plan.ChainID, Signer: plan.Signer}
	return exportSavedBlock(journalPath, identity, plan.ParentHash, output, func(journal *SigningJournal, block *types.Block) error {
		if journal.policy == nil || *journal.policy != approval.Policy {
			return fmt.Errorf("export approval differs from journal policy")
		}
		header := block.Header()
		copy(header.Extra[len(header.Extra)-65:], make([]byte, 65))
		unsigned, err := rlp.EncodeToBytes(block.WithSeal(header))
		if err != nil {
			return err
		}
		if !bytes.Equal(unsigned, approval.UnsignedBlock) {
			return fmt.Errorf("saved block differs from approved unsigned bytes")
		}
		return nil
	})
}

package recovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

// SignOffline holds the stopped chain's read-only database lock throughout
// construction and signing. The existing journal must live outside chain data.
// It does not open a key, import a block, export a file or contact the network.
func SignOffline(chainPath, journalPath string, plan Plan, txs types.Transactions, reviewed []byte, signer datong.SignerFn) (*types.Block, error) {
	identity := SigningIdentity{GenesisHash: plan.GenesisHash, ChainID: plan.ChainID, Signer: plan.Signer}
	return withOfflineJournal(chainPath, journalPath, identity, func(reader *Reader, journal *SigningJournal) (*types.Block, error) {
		return journal.Sign(reader, plan, txs, reviewed, signer)
	})
}

func withOfflineJournal(chainPath, journalPath string, identity SigningIdentity, sign func(*Reader, *SigningJournal) (*types.Block, error)) (*types.Block, error) {
	chainPath, err := existingDirectory(chainPath)
	if err != nil {
		return nil, err
	}
	journalPath, err = existingDirectory(journalPath)
	if err != nil {
		return nil, err
	}
	if containsPath(chainPath, journalPath) || containsPath(journalPath, chainPath) {
		return nil, fmt.Errorf("signing journal and chain data must be separate directories")
	}
	return withStoppedChain(chainPath, func(reader *Reader) (*types.Block, error) {
		journal, err := OpenSigningJournal(journalPath, identity)
		if err != nil {
			return nil, err
		}
		defer journal.Close()
		return sign(reader, journal)
	})
}

func withStoppedChain(chainPath string, use func(*Reader) (*types.Block, error)) (*types.Block, error) {
	db, err := rawdb.NewLevelDBDatabase(chainPath, 16, 16, "recovery-offline", true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	reader, err := NewReader(db)
	if err != nil {
		return nil, err
	}
	return use(reader)
}

// ExportSavedBlock retrieves a completed journal record without any signing
// capability or chain-head dependency. It only creates a new file. A failed
// write can leave a partial file; retry to a new path and verify before import.
func ExportSavedBlock(journalPath string, identity SigningIdentity, parent common.Hash, output string) error {
	return exportSavedBlock(journalPath, identity, parent, output, nil)
}

func exportSavedBlock(journalPath string, identity SigningIdentity, parent common.Hash, output string, check func(*SigningJournal, *types.Block) error) error {
	if !filepath.IsAbs(output) {
		return fmt.Errorf("absolute export filename required")
	}
	journalPath, err := existingDirectory(journalPath)
	if err != nil {
		return err
	}
	directory, err := existingDirectory(filepath.Dir(output))
	if err != nil {
		return err
	}
	output = filepath.Join(directory, filepath.Base(output))
	if containsPath(journalPath, output) {
		return fmt.Errorf("export must be outside signing journal")
	}
	journal, err := OpenSigningJournal(journalPath, identity)
	if err != nil {
		return err
	}
	defer journal.Close()
	block, err := journal.Saved(parent)
	if err != nil {
		return err
	}
	if check != nil {
		if err := check(journal, block); err != nil {
			return err
		}
	}
	encoded, err := rlp.EncodeToBytes(block)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func existingDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("absolute existing directory required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve existing directory %q: %w", path, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("directory required: %s", path)
	}
	return resolved, nil
}

func containsPath(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

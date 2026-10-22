package restart

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/ethdb"
	"github.com/FusionFoundation/efsn/v5/params"
	"github.com/FusionFoundation/efsn/v5/trie"
)

type stateExportIdentity struct {
	Format         int
	Genesis        common.Hash
	Head           *types.Header
	Config         *params.ChainConfig
	ExecutableHash string
}

type stateExportProgress struct {
	FetchedNodes uint64
	FetchedCode  uint64
	FetchedBytes uint64
	Batches      uint64
}

func createStateExportDirectory(directory string, identity stateExportIdentity) error {
	if !filepath.IsAbs(directory) {
		return errors.New("state export requires an absolute new directory")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return fmt.Errorf("state export requires a new directory: %w", err)
	}
	return writeStateExportJSON(filepath.Join(directory, "identity.json"), identity)
}

func writeStateExportJSON(path string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func exportState(source ethdb.KeyValueReader, target ethdb.Database, root common.Hash, checkpoint func(stateExportProgress) error) (stateExportProgress, error) {
	var progress stateExportProgress
	iterator := target.NewIterator(nil, nil)
	occupied := iterator.Next()
	err := iterator.Error()
	iterator.Release()
	if err != nil {
		return progress, err
	}
	if occupied {
		return progress, errors.New("state export requires an empty target database")
	}
	scheduler := state.NewStateSync(root, target, nil, nil)
	for scheduler.Pending() > 0 {
		if err := checkpoint(progress); err != nil {
			return progress, err
		}
		nodes, _, codes := scheduler.Missing(512)
		if len(nodes)+len(codes) == 0 {
			return progress, errors.New("state export scheduler stalled")
		}
		for _, hash := range nodes {
			data := rawdb.ReadTrieNode(source, hash)
			if err := supplyStateExportBlob(scheduler, hash, data); err != nil {
				return progress, fmt.Errorf("state node %s: %w", hash.Hex(), err)
			}
			progress.FetchedNodes++
			progress.FetchedBytes += uint64(len(data))
		}
		for _, hash := range codes {
			data := rawdb.ReadCode(source, hash)
			if err := supplyStateExportBlob(scheduler, hash, data); err != nil {
				return progress, fmt.Errorf("state code/data %s: %w", hash.Hex(), err)
			}
			progress.FetchedCode++
			progress.FetchedBytes += uint64(len(data))
		}
		batch := target.NewBatch()
		if err := scheduler.Commit(batch); err != nil {
			return progress, err
		}
		if err := checkpoint(progress); err != nil {
			return progress, err
		}
		if batch.ValueSize() > 0 {
			if err := batch.Write(); err != nil {
				return progress, err
			}
			progress.Batches++
		}
	}
	return progress, nil
}

func supplyStateExportBlob(scheduler *trie.Sync, hash common.Hash, data []byte) error {
	if len(data) == 0 || crypto.Keccak256Hash(data) != hash {
		return errors.New("missing blob or content hash mismatch")
	}
	err := scheduler.Process(trie.SyncResult{Hash: hash, Data: data})
	if errors.Is(err, trie.ErrAlreadyProcessed) || errors.Is(err, trie.ErrNotRequested) {
		return nil
	}
	return err
}

package restart

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/ethdb"
	"github.com/FusionFoundation/efsn/v5/params"
	"github.com/FusionFoundation/efsn/v5/rlp"
	"github.com/FusionFoundation/efsn/v5/trie"
)

type stateInspection struct {
	Accounts       uint64
	StorageLeaves  uint64
	CodeReferences uint64
	CodeBytes      uint64
}

func inspectState(db ethdb.Database, root common.Hash, progress func(stateInspection)) (stateInspection, error) {
	var result stateInspection
	cache := state.NewDatabase(db)
	accounts, err := cache.OpenTrie(root)
	if err != nil {
		return result, err
	}
	err = inspectTrie(accounts, root, func(key, value []byte) error {
		var account state.Account
		if err := rlp.DecodeBytes(value, &account); err != nil {
			return fmt.Errorf("account %x: %w", key, err)
		}
		storage, err := cache.OpenStorageTrie(common.BytesToHash(key), account.Root)
		if err != nil {
			return fmt.Errorf("account %x storage: %w", key, err)
		}
		if err := inspectTrie(storage, account.Root, func(_, _ []byte) error {
			result.StorageLeaves++
			return nil
		}); err != nil {
			return fmt.Errorf("account %x storage: %w", key, err)
		}
		if !bytes.Equal(account.CodeHash, crypto.Keccak256(nil)) {
			code, err := cache.ContractCode(common.BytesToHash(key), common.BytesToHash(account.CodeHash))
			if err != nil {
				return fmt.Errorf("account %x code: %w", key, err)
			}
			if !bytes.Equal(crypto.Keccak256(code), account.CodeHash) {
				return fmt.Errorf("account %x code hash mismatch", key)
			}
			result.CodeReferences++
			result.CodeBytes += uint64(len(code))
		}
		result.Accounts++
		progress(result)
		return nil
	})
	return result, err
}

func inspectTrie(source state.Trie, root common.Hash, visit func([]byte, []byte) error) error {
	rebuilt := trie.NewStackTrie(nil)
	iterator := trie.NewIterator(source.NodeIterator(nil))
	for iterator.Next() {
		if len(iterator.Key) != common.HashLength {
			return fmt.Errorf("unexpected secure-trie key length %d", len(iterator.Key))
		}
		if err := visit(iterator.Key, iterator.Value); err != nil {
			return err
		}
		if err := rebuilt.TryUpdate(common.CopyBytes(iterator.Key), common.CopyBytes(iterator.Value)); err != nil {
			return err
		}
	}
	if iterator.Err != nil {
		return iterator.Err
	}
	if root == (common.Hash{}) {
		root = types.EmptyRootHash
	}
	if actual := rebuilt.Hash(); actual != root {
		return fmt.Errorf("rebuilt trie root %s differs from %s", actual.Hex(), root.Hex())
	}
	return nil
}

type historyInspection struct {
	Blocks                    uint64
	Transactions              uint64
	Receipts                  uint64
	ExportRLPBytes            uint64
	AbsentEmptyReceiptRecords uint64
	LastHash                  common.Hash
	TotalDifficulty           *big.Int
}

func inspectHistory(db ethdb.Database, config *params.ChainConfig, end uint64, progress func(historyInspection)) (historyInspection, error) {
	result := historyInspection{TotalDifficulty: new(big.Int)}
	for height := uint64(0); height <= end; height++ {
		hash := rawdb.ReadCanonicalHash(db, height)
		block := rawdb.ReadBlock(db, hash, height)
		if block == nil || block.Hash() != hash || block.NumberU64() != height {
			return result, fmt.Errorf("height %d: missing or inconsistent canonical block", height)
		}
		if height > 0 && block.ParentHash() != result.LastHash {
			return result, fmt.Errorf("height %d: parent link mismatch", height)
		}
		number := rawdb.ReadHeaderNumber(db, hash)
		if number == nil || *number != height {
			return result, fmt.Errorf("height %d: hash-to-number index mismatch", height)
		}
		if types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil)) != block.TxHash() {
			return result, fmt.Errorf("height %d: transaction commitment mismatch", height)
		}
		receiptData := rawdb.ReadReceiptsRLP(db, hash, height)
		var storedReceipts []*types.ReceiptForStorage
		if len(receiptData) != 0 {
			if err := rlp.DecodeBytes(receiptData, &storedReceipts); err != nil {
				return result, fmt.Errorf("height %d: invalid receipt encoding: %w", height, err)
			}
		}
		receipts := make(types.Receipts, len(storedReceipts))
		for i, receipt := range storedReceipts {
			if receipt == nil {
				return result, fmt.Errorf("height %d: nil stored receipt", height)
			}
			receipts[i] = (*types.Receipt)(receipt)
		}
		if len(receiptData) == 0 && len(block.Transactions()) == 0 && block.ReceiptHash() == types.EmptyRootHash {
			result.AbsentEmptyReceiptRecords++
		}
		if len(receipts) != len(block.Transactions()) {
			return result, fmt.Errorf("height %d: receipt count mismatch", height)
		}
		if err := receipts.DeriveFields(config, hash, height, block.Transactions()); err != nil {
			return result, fmt.Errorf("height %d: receipt metadata: %w", height, err)
		}
		if types.DeriveSha(receipts, trie.NewStackTrie(nil)) != block.ReceiptHash() || types.CreateBloom(receipts) != block.Bloom() {
			return result, fmt.Errorf("height %d: receipt commitment or bloom mismatch", height)
		}
		result.TotalDifficulty.Add(result.TotalDifficulty, block.Difficulty())
		storedDifficulty := rawdb.ReadTd(db, hash, height)
		if storedDifficulty == nil || storedDifficulty.Cmp(result.TotalDifficulty) != 0 {
			return result, fmt.Errorf("height %d: accumulated difficulty mismatch", height)
		}
		result.Blocks++
		result.Transactions += uint64(len(block.Transactions()))
		result.Receipts += uint64(len(receipts))
		result.ExportRLPBytes += uint64(block.Size())
		result.LastHash = hash
		progress(result)
	}
	return result, nil
}

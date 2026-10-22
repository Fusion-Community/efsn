package restart

import (
	"fmt"
	"math/big"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/trie"
)

type fullStateContext struct {
	Headers         []*types.Header
	Parent          *types.Block
	TotalDifficulty *big.Int
	Receipts        types.Receipts
}

func validateFullStateContext(context *fullStateContext, expected common.Hash) error {
	if len(context.Headers) != 256 || context.Parent == nil || context.TotalDifficulty == nil || context.TotalDifficulty.Sign() <= 0 {
		return fmt.Errorf("incomplete full-state context")
	}
	for i, header := range context.Headers {
		if header == nil || header.Number == nil {
			return fmt.Errorf("missing context header %d", i)
		}
		if i > 0 && (header.Number.Uint64() != context.Headers[i-1].Number.Uint64()+1 || header.ParentHash != context.Headers[i-1].Hash()) {
			return fmt.Errorf("broken context ancestry at %d", i)
		}
	}
	parent := context.Parent
	if parent.Hash() != expected || context.Headers[255].Hash() != expected {
		return fmt.Errorf("context does not terminate at preserved parent")
	}
	if types.DeriveSha(parent.Transactions(), trie.NewStackTrie(nil)) != parent.TxHash() || len(parent.Uncles()) != 0 {
		return fmt.Errorf("context parent body commitment mismatch")
	}
	if len(context.Receipts) != len(parent.Transactions()) || types.DeriveSha(context.Receipts, trie.NewStackTrie(nil)) != parent.ReceiptHash() || types.CreateBloom(context.Receipts) != parent.Bloom() {
		return fmt.Errorf("context parent receipts mismatch")
	}
	return nil
}

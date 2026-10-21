package ticketgzip_test

import (
	"testing"

	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/params"
)

func TestMainnetGenesisHash(t *testing.T) {
	if hash := core.DefaultGenesisBlock().ToBlock(nil).Hash(); hash != params.MainnetGenesisHash {
		t.Fatalf("mainnet genesis hash mismatch: have %x, want %x", hash, params.MainnetGenesisHash)
	}
}

package datong

import (
	"encoding/binary"
	"math/big"
	"strings"
	"testing"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/params"
)

// A producer killed with kill -9 restarts on the last head whose state reached disk, which can
// be far below the blocks it already sealed. Sealing again from there signs a second block on
// a parent it already signed on, which DaTong reports as illegal and punishes by deleting the
// producer's tickets. After a restart on the same database the engine must refuse those heights.
func TestSealRefusesHeightsSealedBeforeRestart(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	sealed := make([]byte, 8)
	binary.BigEndian.PutUint64(sealed, 15131755)
	if err := db.Put([]byte("datong-last-sealed"), sealed); err != nil {
		t.Fatal(err)
	}
	signer := common.HexToAddress("0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF")
	signFn := func(accounts.Account, string, []byte) ([]byte, error) { return make([]byte, extraSeal), nil }

	restarted := New(&params.DaTongConfig{}, db)
	restarted.Authorize(signer, signFn)
	for _, number := range []int64{15130084, 15131755} {
		block := types.NewBlockWithHeader(&types.Header{Number: big.NewInt(number), Coinbase: signer, Extra: make([]byte, extraVanity+extraSeal)})
		err := restarted.Seal(nil, block, make(chan *types.Block, 1), make(chan struct{}))
		if err == nil || !strings.Contains(err.Error(), "refusing to seal") {
			t.Fatalf("block %d: got %v, want a refusal", number, err)
		}
	}
}

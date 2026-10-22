package datong

import (
	"math/big"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/params"
)

func TestCheckPointAboveLastCheckPoint(t *testing.T) {
	InitCheckPoints("")
	mainnet, private := params.MainnetChainConfig.ChainID, big.NewInt(1337)
	pinned := common.HexToHash("0xe93ffded087a79097d4309c7831690161db6ed136f4b1a22c4c83a99db80f99f")
	other := common.HexToHash("0x01")
	cases := []struct {
		chainID      *big.Int
		height       uint64
		hash         common.Hash
		inRange, bad bool
	}{
		{mainnet, 15130080, pinned, false, false},
		{mainnet, 15130080, other, false, true},
		{mainnet, 15130081, other, false, false},
		{mainnet, 2680000, other, true, true},
		{private, 15130080, other, false, false},
	}
	for _, c := range cases {
		inRange, err := CheckPoint(c.chainID, c.height, c.hash)
		if inRange != c.inRange || (err != nil) != c.bad {
			t.Errorf("CheckPoint(%v, %d, %x) = %v, %v", c.chainID, c.height, c.hash, inRange, err)
		}
	}
	headers := []*types.Header{{Number: big.NewInt(15130079)}, {Number: big.NewInt(15130080)}}
	if i, err := CheckPointsInHeaderChain(mainnet, headers); i != 1 || err == nil {
		t.Errorf("CheckPointsInHeaderChain = %d, %v", i, err)
	}
	rollbacks := []struct {
		chainID          *big.Int
		oldHead, newHead uint64
		want             bool
	}{
		{mainnet, 15130090, 15130079, true},
		{mainnet, 15130090, 15130080, false},
		{mainnet, 15130079, 15130000, false},
		{private, 15130090, 15130079, false},
	}
	for _, c := range rollbacks {
		if got := IsCheckPointRollback(c.chainID, c.oldHead, c.newHead); got != c.want {
			t.Errorf("IsCheckPointRollback(%v, %d, %d) = %v", c.chainID, c.oldHead, c.newHead, got)
		}
	}
}

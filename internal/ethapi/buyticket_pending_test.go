package ethapi

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/common/hexutil"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/params"
	"github.com/FusionFoundation/efsn/v5/rlp"
	"github.com/FusionFoundation/efsn/v5/rpc"
)

type pendingTicketBackend struct {
	Backend
	pending *types.Transaction
}

func (b *pendingTicketBackend) ChainConfig() *params.ChainConfig { return params.MainnetChainConfig }

func (b *pendingTicketBackend) StateAndHeaderByNumber(context.Context, rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	statedb, err := state.New(common.Hash{}, common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	return statedb, &types.Header{Number: big.NewInt(15130124), Time: 1790490000}, err
}

func (b *pendingTicketBackend) GetPoolTransactionByPredicate(predicate func(*types.Transaction) bool) *types.Transaction {
	if b.pending != nil && predicate(b.pending) {
		return b.pending
	}
	return nil
}

func TestBuyTicketRefusedWhilePurchasePending(t *testing.T) {
	key, err := crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000002")
	if err != nil {
		t.Fatal(err)
	}
	owner := crypto.PubkeyToAddress(key.PublicKey)
	purchase, err := rlp.EncodeToBytes(&common.BuyTicketParam{Start: 1790488672, End: 1793083767})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := rlp.EncodeToBytes(&common.FSNCallParam{Func: common.BuyTicketFunc, Data: purchase})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := types.SignTx(types.NewTransaction(9, common.FSNCallAddress, new(big.Int), 21224, big.NewInt(1000000001), payload), types.LatestSigner(params.MainnetChainConfig), key)
	if err != nil {
		t.Fatal(err)
	}
	same, other := hexutil.Uint64(9), hexutil.Uint64(10)
	cases := []struct {
		pending *types.Transaction
		nonce   *hexutil.Uint64
		refused bool
	}{
		{tx, nil, true},
		{tx, &other, true},
		{tx, &same, false},
		{nil, nil, false},
	}
	for i, c := range cases {
		api := NewPublicFusionAPI(&pendingTicketBackend{pending: c.pending})
		_, err := api.BuildBuyTicketSendTxArgs(context.Background(), common.BuyTicketArgs{FusionBaseArgs: common.FusionBaseArgs{From: owner, Nonce: c.nonce}})
		if refused := err != nil && strings.Contains(err.Error(), "already pending"); refused != c.refused {
			t.Errorf("case %d: err=%v, want refused=%v", i, err, c.refused)
		}
	}
}

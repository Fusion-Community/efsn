package tracing

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/core/vm"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/FusionFoundation/efsn/v5/eth"
	"github.com/FusionFoundation/efsn/v5/eth/ethconfig"
	"github.com/FusionFoundation/efsn/v5/eth/tracers"
	_ "github.com/FusionFoundation/efsn/v5/eth/tracers/native"
	"github.com/FusionFoundation/efsn/v5/node"
	"github.com/FusionFoundation/efsn/v5/p2p"
	"github.com/FusionFoundation/efsn/v5/params"
	"github.com/FusionFoundation/efsn/v5/rlp"
	"github.com/FusionFoundation/efsn/v5/rpc"
	"github.com/stretchr/testify/require"
)

func TestHistoricalStateReplay(t *testing.T) {
	producer := newTracingNode(t)
	blocks := makeTracingBlocks(t, producer, 4)
	for _, saved := range []int{0, 2} {
		for _, checkLive := range []bool{false, true} {
			t.Run(fmt.Sprintf("saved=%d/checkLive=%t", saved, checkLive), func(t *testing.T) {
				reader := newTracingNode(t)
				if saved > 0 {
					_, err := reader.BlockChain().InsertChain(blocks[:saved])
					require.NoError(t, err)
				}
				copyTracingHistory(reader, blocks[saved:])
				last := blocks[len(blocks)-1]
				_, missing := state.New(last.Root(), last.MixDigest(), state.NewDatabase(reader.ChainDb()))
				require.Error(t, missing)
				expected, err := producer.BlockChain().StateAt(last.Root(), last.MixDigest())
				require.NoError(t, err)
				expectedTickets, err := expected.AllTickets()
				require.NoError(t, err)

				actual, err := reader.APIBackend.StateAtBlock(context.Background(), last, 4, nil, checkLive, false)

				require.NoError(t, err)
				tickets, err := actual.AllTickets()
				require.NoError(t, err)
				require.Equal(t, expectedTickets, tickets)
				require.Equal(t, last.Root(), actual.IntermediateRoot(true))
				require.Equal(t, big.NewInt(28), actual.GetBalance(common.SystemAssetID, common.Address{19: 0x22}))
				_, missing = state.New(last.Root(), last.MixDigest(), state.NewDatabase(reader.ChainDb()))
				require.Error(t, missing)
			})
		}
	}
	t.Run("continuation", func(t *testing.T) {
		reader := newTracingNode(t)
		copyTracingHistory(reader, blocks)
		base, err := reader.APIBackend.StateAtBlock(context.Background(), reader.BlockChain().Genesis(), 0, nil, false, false)
		require.NoError(t, err)
		for _, block := range blocks {
			base, err = reader.APIBackend.StateAtBlock(context.Background(), block, 0, base, false, true)
			require.NoError(t, err)
			tickets, err := base.AllTickets()
			require.NoError(t, err)
			require.Equal(t, uint64(16)-block.NumberU64(), tickets.NumberOfTickets())
			require.Equal(t, block.Root(), base.IntermediateRoot(true))
		}
	})
	t.Run("reexec limit", func(t *testing.T) {
		reader := newTracingNode(t)
		copyTracingHistory(reader, blocks)

		_, err := reader.APIBackend.StateAtBlock(context.Background(), blocks[3], 1, nil, true, false)

		require.EqualError(t, err, "required historical state unavailable (reexec=1)")
	})
	t.Run("invalid commitment", func(t *testing.T) {
		reader := newTracingNode(t)
		_, err := reader.BlockChain().InsertChain(blocks[:3])
		require.NoError(t, err)
		header := blocks[3].Header()
		header.MixDigest = common.Hash{31: 1}
		invalid := signTracingBlock(t, blocks[3].WithSeal(header))
		copyTracingHistory(reader, types.Blocks{invalid})

		_, replayErr := reader.APIBackend.StateAtBlock(context.Background(), invalid, 4, nil, false, false)
		_, importErr := reader.BlockChain().InsertChain(types.Blocks{invalid})

		require.Error(t, replayErr)
		require.Contains(t, replayErr.Error(), "MixDigest mismatch")
		require.Error(t, importErr)
		require.Contains(t, importErr.Error(), "MixDigest mismatch")
		require.Equal(t, blocks[2].Hash(), reader.BlockChain().CurrentBlock().Hash())
	})
}

func TestHistoricalCallTracing(t *testing.T) {
	producer := newTracingNode(t)
	blocks := makeTracingBlocks(t, producer, 4)
	reader := newTracingNode(t)
	copyTracingHistory(reader, blocks)
	api := tracers.NewAPI(reader.APIBackend)
	name, reexec := "callTracer", uint64(4)
	config := &tracers.TraceConfig{Tracer: &name, Reexec: &reexec}
	expected := []callFrame{{Type: "CALL", From: common.Address{19: 0x11}, To: common.Address{19: 0x22}, Value: "0x7"}}
	for _, byHash := range []bool{false, true} {
		t.Run(fmt.Sprintf("block/byHash=%t", byHash), func(t *testing.T) {
			var encoded []byte
			if byHash {
				result, err := api.TraceBlockByHash(context.Background(), blocks[3].Hash(), config)
				require.NoError(t, err)
				encoded, err = json.Marshal(result)
				require.NoError(t, err)
			} else {
				result, err := api.TraceBlockByNumber(context.Background(), 4, config)
				require.NoError(t, err)
				encoded, err = json.Marshal(result)
				require.NoError(t, err)
			}
			var result []traceResult
			require.NoError(t, json.Unmarshal(encoded, &result))
			require.Len(t, result, 1)
			require.Empty(t, result[0].Error)
			require.Empty(t, result[0].Result.Error)
			require.Equal(t, expected, result[0].Result.Calls)
		})
	}
	t.Run("transaction", func(t *testing.T) {
		result, err := api.TraceTransaction(context.Background(), blocks[3].Transactions()[0].Hash(), config)
		require.NoError(t, err)
		encoded, err := json.Marshal(result)
		require.NoError(t, err)
		var frame callFrame
		require.NoError(t, json.Unmarshal(encoded, &frame))
		require.Empty(t, frame.Error)
		require.Equal(t, expected, frame.Calls)
	})
	t.Run("chain", func(t *testing.T) {
		server := rpc.NewServer()
		require.NoError(t, server.RegisterName("debug", api))
		t.Cleanup(server.Stop)
		client := rpc.DialInProc(server)
		t.Cleanup(client.Close)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		results := make(chan chainTraceResult, 4)
		subscription, err := client.Subscribe(ctx, "debug", results, "traceChain", "0x0", "0x4", config)
		require.NoError(t, err)
		defer subscription.Unsubscribe()
		for i := 0; i < 4; i++ {
			select {
			case result := <-results:
				require.Equal(t, blocks[i].Hash(), result.Hash)
				require.Len(t, result.Traces, 1)
				require.Empty(t, result.Traces[0].Error)
				require.Empty(t, result.Traces[0].Result.Error)
				require.Equal(t, expected, result.Traces[0].Result.Calls)
			case <-ctx.Done():
				t.Fatal("traceChain did not return all blocks")
			}
		}
	})
}

type callFrame struct {
	Type  string
	From  common.Address
	To    common.Address
	Value string
	Error string
	Calls []callFrame
}

type traceResult struct {
	Result callFrame
	Error  string
}

type chainTraceResult struct {
	Hash   common.Hash
	Traces []traceResult
}

func newTracingNode(t *testing.T) *eth.Ethereum {
	t.Helper()
	key := tracingKey(t)
	owner := crypto.PubkeyToAddress(key.PublicKey)
	chainConfig := *params.MainnetChainConfig
	chainConfig.ChainID = big.NewInt(1337)
	config := ethconfig.Defaults
	config.Genesis = &core.Genesis{
		Config: &chainConfig, Timestamp: 1600000000, GasLimit: 8000000, Difficulty: big.NewInt(1),
		TicketCreateInfo: &core.TicketsCreate{Owner: owner, Count: 16, Time: 1600000000},
		Alloc: core.GenesisAlloc{
			owner:      {Balance: big.NewInt(1000000000000000000)},
			{19: 0x11}: {Balance: big.NewInt(1000), Code: common.FromHex("6000600060006000600773000000000000000000000000000000000000002261fffff15000")},
		},
	}
	config.NoPruning = true
	config.DatabaseCache, config.TrieCleanCache, config.TrieDirtyCache = 16, 16, 0
	config.TxPool.Journal = ""
	stack, err := node.New(&node.Config{P2P: p2p.Config{PrivateKey: key, NoDiscovery: true, NoDial: true}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, stack.Close()) })
	backend, err := eth.New(stack, &config)
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	return backend
}

func tracingKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.HexToECDSA("0000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err)
	return key
}

func makeTracingBlocks(t *testing.T, backend *eth.Ethereum, count int) types.Blocks {
	t.Helper()
	chain, key := backend.BlockChain(), tracingKey(t)
	owner := crypto.PubkeyToAddress(key.PublicKey)
	blocks := make(types.Blocks, 0, count)
	for i := 0; i < count; i++ {
		parent := chain.CurrentBlock()
		header := &types.Header{ParentHash: parent.Hash(), Number: new(big.Int).Add(parent.Number(), common.Big1), Time: parent.Time() + 15, GasLimit: parent.GasLimit(), Coinbase: owner}
		require.NoError(t, backend.Engine().Prepare(chain, header))
		statedb, err := chain.State()
		require.NoError(t, err)
		tx, err := types.SignTx(types.NewTransaction(uint64(i), common.Address{19: 0x11}, big.NewInt(0), 100000, big.NewInt(1), nil), types.MakeSigner(chain.Config(), header.Number), key)
		require.NoError(t, err)
		statedb.Prepare(tx.Hash(), 0)
		receipt, err := core.ApplyTransaction(chain.Config(), chain, &owner, new(core.GasPool).AddGas(header.GasLimit), statedb, header, tx, &header.GasUsed, vm.Config{})
		require.NoError(t, err)
		require.Equal(t, uint64(1), receipt.Status)
		block, err := backend.Engine().Finalize(chain, header, statedb, []*types.Transaction{tx}, nil, []*types.Receipt{receipt})
		require.NoError(t, err)
		block = signTracingBlock(t, block)
		_, err = chain.InsertChain(types.Blocks{block})
		require.NoError(t, err)
		blocks = append(blocks, block)
	}
	return blocks
}

func signTracingBlock(t *testing.T, block *types.Block) *types.Block {
	t.Helper()
	header := block.Header()
	encoded, err := rlp.EncodeToBytes([]interface{}{header.ParentHash, header.UncleHash, header.Coinbase, header.Root, header.TxHash, header.ReceiptHash, header.Bloom, header.Difficulty, header.Number, header.GasLimit, header.GasUsed, header.Time, header.Extra[:len(header.Extra)-65], header.MixDigest, header.Nonce})
	require.NoError(t, err)
	signature, err := crypto.Sign(crypto.Keccak256(encoded), tracingKey(t))
	require.NoError(t, err)
	copy(header.Extra[len(header.Extra)-65:], signature)
	encoded, err = rlp.EncodeToBytes(block.WithSeal(header))
	require.NoError(t, err)
	var received types.Block
	require.NoError(t, rlp.DecodeBytes(encoded, &received))
	return &received
}

func copyTracingHistory(backend *eth.Ethereum, blocks types.Blocks) {
	for _, block := range blocks {
		rawdb.WriteBlock(backend.ChainDb(), block)
		rawdb.WriteCanonicalHash(backend.ChainDb(), block.Hash(), block.NumberU64())
		rawdb.WriteTxLookupEntriesByBlock(backend.ChainDb(), block)
	}
}

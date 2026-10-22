package restart

import (
	"context"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/accounts/keystore"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/common/hexutil"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/internal/ethapi"
)

func TestSubmittedTicketReplacementAllowsExplicitRetry(t *testing.T) {
	if os.Getenv("FUSION_RESTART_REPLACEMENT_CHILD") == "1" {
		runSubmittedTicketReplacement(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSubmittedTicketReplacementAllowsExplicitRetry$", "-test.v", "-test.timeout=25s")
	command.Env = append(os.Environ(), "FUSION_RESTART_REPLACEMENT_CHILD=1")
	output, err := command.CombinedOutput()
	t.Logf("isolated replacement scenario:\n%s", output)
	requireNoError(t, err)
}

func runSubmittedTicketReplacement(t *testing.T) {
	f := newFixture(t)
	f.importBlock(t, f.buildBlock(t, f.parent.Time()+120, false))
	keys := keystore.NewKeyStore(t.TempDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := keys.ImportECDSA(f.key, "synthetic-test-key")
	requireNoError(t, err)
	requireNoError(t, keys.Unlock(account, "synthetic-test-key"))
	manager := accounts.NewManager(keys)
	t.Cleanup(func() { manager.Close() })
	b := &autoBuyBackend{purchaseBackend: &purchaseBackend{chain: f.chain}, pool: f.newPool(t), accounts: manager, owner: f.owner, submissions: make(chan purchaseSubmission, 8)}
	lock := new(ethapi.AddrLocker)
	api := ethapi.NewFusionTransactionAPI(b, lock, ethapi.NewPublicTransactionPoolAPI(b, lock))
	end := hexutil.Uint64(common.TimeLockForever)
	args := common.BuyTicketArgs{FusionBaseArgs: common.FusionBaseArgs{From: f.owner}, End: &end}
	hash, err := api.BuyTicket(context.Background(), args)
	requireNoError(t, err)
	submitted := awaitSubmission(t, b)
	requireNoError(t, submitted.err)
	if submitted.tx.Hash() != hash || b.pool.Get(hash) == nil {
		t.Fatal("purchase was not actually accepted into the pool")
	}
	price := new(big.Int).Mul(submitted.tx.GasPrice(), big.NewInt(2))
	replacement, err := types.SignTx(types.NewTransaction(submitted.tx.Nonce(), f.owner, big.NewInt(0), 21000, price, nil), types.LatestSigner(f.chain.Config()), f.key)
	requireNoError(t, err)
	requireNoError(t, b.pool.AddLocal(replacement))
	if b.pool.Get(hash) != nil || b.pool.Get(replacement.Hash()) == nil {
		t.Fatal("pool did not replace the purchase with the same-nonce transfer")
	}

	retriedHash, err := api.BuyTicket(context.Background(), args)

	requireNoError(t, err)
	retried := awaitSubmission(t, b)
	if retried.tx.Hash() != retriedHash || retried.tx.Nonce() != submitted.tx.Nonce()+1 || b.pool.Get(retriedHash) == nil {
		t.Fatal("explicit retry did not respect the replacement transaction's nonce")
	}
	if f.chain.CurrentBlock().NumberU64() != 15130081 {
		t.Fatal("replacement scenario unexpectedly advanced the chain")
	}
	t.Log("explicit retry used the next available nonce after the pool replacement; no stale submitted cache")
}

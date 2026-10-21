package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/common/hexutil"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/internal/recovery"
	"github.com/FusionFoundation/efsn/v5/params"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

type report struct {
	Version       uint64
	Plan          recovery.Plan
	ChainConfig   *params.ChainConfig
	UnsignedBlock hexutil.Bytes
	Header        *types.Header
	Receipt       *types.Receipt
	Ticket        common.Ticket
	Selected      common.Hash
	Retreat       []common.Hash
}

func main() {
	if err := run(); err != nil {
		if err == flag.ErrHelp {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	return runCommand(os.Args[1:])
}

func runReview(args []string) error {
	flags := flag.NewFlagSet("review", flag.ContinueOnError)
	directory := flags.String("chaindata", "", "absolute path to a stopped LevelDB database; opened read-only")
	planPath := flags.String("plan", "", "reviewed recovery plan JSON")
	purchasePath := flags.String("purchase", "", "one already-signed purchase transaction in binary RLP")
	output := flags.String("out", "", "new absolute report filename; existing files are refused")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*directory) || !filepath.IsAbs(*output) || *planPath == "" || *purchasePath == "" {
		return fmt.Errorf("required: -chaindata ABSOLUTE_PATH -plan PLAN.json -purchase TX.rlp -out NEW_ABSOLUTE_REPORT.json")
	}
	planData, err := readInput(*planPath)
	if err != nil {
		return err
	}
	var plan recovery.Plan
	decoder := json.NewDecoder(bytes.NewReader(planData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return err
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		return fmt.Errorf("plan must contain exactly one JSON object")
	}
	purchaseData, err := readInput(*purchasePath)
	if err != nil {
		return err
	}
	var purchase types.Transaction
	if err := rlp.DecodeBytes(purchaseData, &purchase); err != nil {
		return err
	}
	result, err := buildReviewReport(*directory, plan, &purchase)
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, result); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Prepared unsigned recovery candidate. No block signature, database commit or network publication occurred.")
	return nil
}

func buildReviewReport(directory string, plan recovery.Plan, purchase *types.Transaction) ([]byte, error) {
	db, err := rawdb.NewLevelDBDatabase(directory, 128, 64, "recovery-readonly", true)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	chain, err := recovery.NewReader(db)
	if err != nil {
		return nil, err
	}
	candidate, err := recovery.Build(chain, plan, types.Transactions{purchase})
	if err != nil {
		return nil, err
	}
	encoded, err := rlp.EncodeToBytes(candidate.Block)
	if err != nil {
		return nil, err
	}
	result, err := json.MarshalIndent(report{Version: 1, Plan: plan, ChainConfig: chain.Config(), UnsignedBlock: encoded, Header: candidate.Block.Header(), Receipt: candidate.Receipt, Ticket: candidate.Ticket, Selected: candidate.Selected, Retreat: candidate.Retreat}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(result, '\n'), nil
}

func readInput(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const limit = 1 << 20
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("input exceeds one MiB: %s", path)
	}
	return data, nil
}

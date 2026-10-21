package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/internal/recovery"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

func runCommand(args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runReview(args)
	}
	switch args[0] {
	case "review":
		return runReview(args[1:])
	case "prepare":
		return runPrepare(args[1:])
	case "init-journal", "sign", "export":
		return runOperator(args[0], args[1:])
	default:
		return fmt.Errorf("expected review, prepare, init-journal, sign or export")
	}
}

func runPrepare(args []string) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	directory := flags.String("chaindata", "", "absolute stopped chain used to verify the complete report")
	reportPath := flags.String("report", "", "reviewed unsigned report")
	purchasePath := flags.String("purchase", "", "signed purchase RLP")
	count := flags.Uint64("blocks", 0, "first stage only: 1 backup block or 2 donation blocks")
	previous := flags.String("policy-from", "", "first approval from the same signer, for its next stage")
	previousHash := flags.String("policy-sha256", "", "separately reviewed SHA-256 of that first approval")
	output := flags.String("out", "", "new absolute approval JSON filename")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*directory) || *reportPath == "" || *purchasePath == "" || !filepath.IsAbs(*output) || ((*previous == "") == (*count == 0)) || (*previous == "" && *previousHash != "") {
		return fmt.Errorf("prepare requires report, purchase, new absolute out, and either blocks or policy-from with policy-sha256")
	}
	data, err := readInput(*reportPath)
	if err != nil {
		return err
	}
	var reviewed report
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reviewed); err != nil {
		return err
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF || reviewed.Version != 1 {
		return fmt.Errorf("one version 1 report required")
	}
	purchase, err := readInput(*purchasePath)
	if err != nil {
		return err
	}
	var tx types.Transaction
	if err := rlp.DecodeBytes(purchase, &tx); err != nil || tx.Hash() != reviewed.Plan.Purchase.Hash {
		return fmt.Errorf("purchase differs from reviewed report")
	}
	expectedReport, err := buildReviewReport(*directory, reviewed.Plan, &tx)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, expectedReport) {
		return fmt.Errorf("report differs from the complete rebuilt canonical report")
	}
	executable, err := recovery.ExecutableSHA256()
	if err != nil {
		return err
	}
	config, err := recovery.ConfigurationSHA256(reviewed.ChainConfig)
	if err != nil {
		return err
	}
	plan := reviewed.Plan
	policy := recovery.SigningPolicy{FirstParent: plan.ParentHash, FirstParentNumber: plan.ParentNumber, PurchaseOwner: plan.Purchase.Owner, BlockCount: *count, ExecutableSHA256: executable, ConfigSHA256: config}
	if *previous != "" {
		priorData, err := readInput(*previous)
		if err != nil {
			return err
		}
		checksum, err := parseDigest(*previousHash)
		if err != nil {
			return err
		}
		prior, err := recovery.DecodeSigningApproval(priorData, checksum)
		if err != nil {
			return err
		}
		if prior.Plan.Signer != plan.Signer || prior.Plan.GenesisHash != plan.GenesisHash || prior.Plan.ChainID != plan.ChainID || prior.Policy.ExecutableSHA256 != executable || prior.Policy.ConfigSHA256 != config {
			return fmt.Errorf("prior approval identity or runtime differs from this report")
		}
		policy = prior.Policy
	}
	if (policy.BlockCount != 1 && policy.BlockCount != 2) || (policy.BlockCount == 1) == (plan.Signer == policy.PurchaseOwner) || policy.PurchaseOwner != plan.Purchase.Owner {
		return fmt.Errorf("invalid handover role or purchaser")
	}
	encoded, err := recovery.EncodeSigningApproval(recovery.SigningApproval{Version: 1, Policy: policy, Plan: plan, Purchase: purchase, UnsignedBlock: reviewed.UnsignedBlock})
	if err != nil {
		return err
	}
	if _, err := recovery.DecodeSigningApproval(encoded, common.Hash(sha256.Sum256(encoded))); err != nil {
		return err
	}
	if err := writeNewFile(*output, encoded); err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Prepared approval for review. SHA256=%x\n", sha256.Sum256(encoded))
	return nil
}

func runOperator(action string, args []string) error {
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	approvalPath := flags.String("approval", "", "canonical reviewed approval JSON")
	digest := flags.String("approved-sha256", "", "separately reviewed approval SHA-256")
	journal := flags.String("journal", "", "absolute journal directory")
	var chainPath, keyPath, output string
	var passwordStdin bool
	if action != "export" {
		flags.StringVar(&chainPath, "chaindata", "", "absolute stopped working chain directory")
	}
	if action == "sign" {
		flags.StringVar(&keyPath, "keyfile", "", "absolute encrypted V3 scrypt key file")
		flags.BoolVar(&passwordStdin, "password-stdin", false, "read one password line from a pipe; terminal input refused")
	}
	if action == "export" {
		flags.StringVar(&output, "out", "", "new absolute RLP filename")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *approvalPath == "" || !filepath.IsAbs(*journal) || (action != "export" && !filepath.IsAbs(chainPath)) || (action == "sign" && (!filepath.IsAbs(keyPath) || !passwordStdin)) || (action == "export" && !filepath.IsAbs(output)) {
		return fmt.Errorf("required explicit approval, approved-sha256, absolute journal and action-specific paths; sign requires password-stdin")
	}
	checksum, err := parseDigest(*digest)
	if err != nil {
		return err
	}
	data, err := readInput(*approvalPath)
	if err != nil {
		return err
	}
	switch action {
	case "init-journal":
		if err := recovery.InitializeApprovedOffline(chainPath, *journal, data, checksum); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "Initialized approved journal. No signature created.")
	case "sign":
		block, err := recovery.SignApprovedKeystore(chainPath, *journal, data, checksum, keyPath, readPasswordStdin)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Completed block retained in journal: %s. Export separately.\n", block.Hash().Hex())
	case "export":
		if err := recovery.ExportApprovedBlock(*journal, data, checksum, output); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "Exported exact approved block. Verify independently before import.")
	}
	return nil
}

func parseDigest(value string) (common.Hash, error) {
	var checksum common.Hash
	if !strings.HasPrefix(value, "0x") {
		value = "0x" + value
	}
	if err := checksum.UnmarshalText([]byte(value)); err != nil || checksum == (common.Hash{}) {
		return common.Hash{}, fmt.Errorf("explicit nonzero 32-byte reviewed SHA-256 required")
	}
	return checksum, nil
}

func readPasswordStdin() ([]byte, error) {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return nil, fmt.Errorf("password input requires a pipe, never an echoing terminal")
	}
	return readPasswordLine(os.Stdin)
}

func readPasswordLine(input io.Reader) ([]byte, error) {
	secret := make([]byte, 0, 4097)
	one := make([]byte, 1)
	for len(secret) <= 4096 {
		_, err := io.ReadFull(input, one)
		if err == io.EOF || (err == nil && one[0] == '\n') {
			if len(secret) > 0 && secret[len(secret)-1] == '\r' {
				secret = secret[:len(secret)-1]
			}
			return secret, nil
		}
		if err != nil {
			return secret, fmt.Errorf("password input failed")
		}
		secret = append(secret, one[0])
	}
	return secret, fmt.Errorf("password exceeds 4096 bytes")
}

func writeNewFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

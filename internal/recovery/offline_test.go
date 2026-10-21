package recovery

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/rlp"
)

func TestExportSavedBlock(t *testing.T) {
	identity, block, encoded, signer := signingFixture(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "journal")
	journal, err := CreateSigningJournal(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := journal.signBlock(block, encoded, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	want, err := rlp.EncodeToBytes(sealed)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "block.rlp")
	if err := ExportSavedBlock(path, identity, block.ParentHash(), output); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("export differs from completed record: %v", err)
	}
	for _, target := range []string{output, filepath.Join(path, "block.rlp"), "relative.rlp"} {
		if err := ExportSavedBlock(path, identity, block.ParentHash(), target); err == nil {
			t.Fatalf("unsafe/existing output accepted: %s", target)
		}
	}
	if err := os.WriteFile(output, want[:len(want)/2], 0600); err != nil {
		t.Fatal(err)
	}
	if err := ExportSavedBlock(path, identity, block.ParentHash(), output); !os.IsExist(err) {
		t.Fatalf("partial export overwritten: %v", err)
	}
	retry := filepath.Join(directory, "recovered.rlp")
	if err := ExportSavedBlock(path, identity, block.ParentHash(), retry); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(retry)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("fresh export did not recover exact record: %v", err)
	}
}

func TestExportSavedBlockRefusesUnfinished(t *testing.T) {
	identity, block, encoded, _ := signingFixture(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "journal")
	journal, err := CreateSigningJournal(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	_, err = journal.signBlock(block, encoded, func(accounts.Account, string, []byte) ([]byte, error) {
		return nil, errors.New("disconnected signer")
	})
	if !errors.Is(err, ErrSigningUncertain) {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "block.rlp")
	if err := ExportSavedBlock(path, identity, block.ParentHash(), output); !errors.Is(err, ErrSigningUncertain) {
		t.Fatalf("unfinished export accepted: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("unfinished export created output: %v", err)
	}
}

func TestOfflineResolvedPaths(t *testing.T) {
	identity, _, _, _ := signingFixture(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "journal")
	journal, err := CreateSigningJournal(path, identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(directory, "alias")
	if err := os.Symlink(path, alias); err != nil {
		if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314)) {
			t.Skipf("Windows symbolic-link privilege unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := SignOffline(alias, path, Plan{}, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "separate") {
		t.Fatalf("aliased chain/journal paths accepted: %v", err)
	}
	if err := ExportSavedBlock(path, identity, identity.GenesisHash, filepath.Join(alias, "block.rlp")); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("aliased journal export accepted: %v", err)
	}
}

package leveldb

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadOnlyCorruptionDoesNotRepair(t *testing.T) {
	path := t.TempDir()
	db, err := New(path, 16, 16, "test", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put([]byte("preserved"), []byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	manifests, err := filepath.Glob(filepath.Join(path, "MANIFEST-*"))
	if err != nil || len(manifests) != 1 {
		t.Fatalf("unexpected manifest inventory: %v %v", manifests, err)
	}
	if err := os.WriteFile(manifests[0], nil, 0600); err != nil {
		t.Fatal(err)
	}
	before := readOnlyFileHashes(t, path)
	readonly, err := New(path, 16, 16, "test", true)
	if err == nil {
		readonly.Close()
		t.Fatal("read-only database silently repaired corruption")
	}
	if after := readOnlyFileHashes(t, path); !reflect.DeepEqual(before, after) {
		t.Fatal("read-only corruption failure altered database files")
	}
	t.Logf("read-only open refused corruption without file changes: %v", err)
}

func readOnlyFileHashes(t *testing.T, path string) map[string][32]byte {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	hashes := make(map[string][32]byte)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		hashes[entry.Name()] = sha256.Sum256(data)
	}
	return hashes
}

package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/accounts/keystore"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/crypto"
	"github.com/syndtr/goleveldb/leveldb"
)

func encryptedTestKey(t *testing.T, path string, scalar int) []byte {
	t.Helper()
	key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", scalar))
	if err != nil {
		t.Fatal(err)
	}
	data, err := keystore.EncryptKey(&keystore.Key{PrivateKey: key, Address: crypto.PubkeyToAddress(key.PublicKey)}, "public test password", 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestKeystoreSessionBoundAndCleared(t *testing.T) {
	identity, block, _, _ := signingFixture(t)
	path := filepath.Join(t.TempDir(), "key.json")
	encrypted := encryptedTestKey(t, path, 1)
	account := accounts.Account{Address: identity.Signer}
	payload := []byte("reviewed public test payload")
	secret := []byte("public test password")
	session, err := openKeystoreSigner(path, account, payload, func() ([]byte, error) { return secret, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("password buffer retained")
	}
	for _, request := range []struct {
		account accounts.Account
		mime    string
		payload []byte
	}{
		{accounts.Account{Address: common.HexToAddress("0x02")}, "", payload},
		{account, "arbitrary", payload},
		{account, "", []byte("different")},
	} {
		if _, err := session.sign(request.account, request.mime, request.payload); err == nil {
			t.Fatal("key signed an unapproved request")
		}
	}
	signature, err := session.sign(account, "", payload)
	if err != nil {
		t.Fatal(err)
	}
	public, err := crypto.SigToPub(crypto.Keccak256(payload), signature)
	if err != nil || crypto.PubkeyToAddress(*public) != block.Coinbase() {
		t.Fatalf("wrong signature: %v", err)
	}
	if _, err := session.sign(account, "", payload); err == nil {
		t.Fatal("second signature permitted")
	}
	session.close()
	if _, err := session.sign(account, "", payload); err == nil {
		t.Fatal("closed key remained usable")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, encrypted) {
		t.Fatal("encrypted source changed")
	}
}

func TestKeystorePreflightDoesNotReserve(t *testing.T) {
	identity, block, encoded, signer := signingFixture(t)
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "key.json")
	encryptedTestKey(t, keyPath, 1)
	journal, err := CreateSigningJournal(filepath.Join(directory, "journal"), identity)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	_, err = journal.signWithPreflight(block, encoded, func(account accounts.Account, payload []byte) (*signingSession, error) {
		return openKeystoreSigner(keyPath, account, payload, func() ([]byte, error) { return []byte("wrong"), nil })
	})
	if err == nil || errors.Is(err, ErrSigningUncertain) {
		t.Fatalf("bad credentials consumed reservation: %v", err)
	}
	if _, err := journal.Saved(block.ParentHash()); err != leveldb.ErrNotFound {
		t.Fatalf("preflight wrote a reservation: %v", err)
	}
	closed := false
	_, err = journal.signWithPreflight(block, encoded, func(accounts.Account, []byte) (*signingSession, error) {
		return &signingSession{sign: signer, close: func() { closed = true }}, nil
	})
	if err != nil || !closed {
		t.Fatalf("successful signing failed to close key: %v", err)
	}
	if _, err := journal.signWithPreflight(block, encoded, func(accounts.Account, []byte) (*signingSession, error) {
		t.Fatal("completed signing reopened a key")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestKeystoreInputBounds(t *testing.T) {
	identity, _, _, _ := signingFixture(t)
	path := filepath.Join(t.TempDir(), "key.json")
	data := encryptedTestKey(t, path, 1)
	for name, change := range map[string]func(map[string]interface{}){
		"kdf_missing": func(k map[string]interface{}) { k["crypto"].(map[string]interface{})["kdfparams"] = nil },
		"kdf_type": func(k map[string]interface{}) {
			k["crypto"].(map[string]interface{})["kdfparams"].(map[string]interface{})["n"] = "262144"
		},
		"kdf_cost": func(k map[string]interface{}) {
			k["crypto"].(map[string]interface{})["kdfparams"].(map[string]interface{})["n"] = 1073741824
		},
		"kdf_fraction": func(k map[string]interface{}) {
			k["crypto"].(map[string]interface{})["kdfparams"].(map[string]interface{})["p"] = 1.5
		},
		"iv_length": func(k map[string]interface{}) {
			k["crypto"].(map[string]interface{})["cipherparams"].(map[string]interface{})["iv"] = "00"
		},
		"scalar_length": func(k map[string]interface{}) { k["crypto"].(map[string]interface{})["ciphertext"] = "00" },
		"version":       func(k map[string]interface{}) { k["version"] = 1 },
		"wrong_address": func(k map[string]interface{}) { k["address"] = "0000000000000000000000000000000000000002" },
	} {
		t.Run(name, func(t *testing.T) {
			var object map[string]interface{}
			if err := json.Unmarshal(data, &object); err != nil {
				t.Fatal(err)
			}
			change(object)
			encoded, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := checkedKeyCrypto(encoded, identity.Signer); err == nil {
				t.Fatal("unsafe key input accepted")
			}
		})
	}
	other := encryptedTestKey(t, path, 2)
	var object map[string]interface{}
	if err := json.Unmarshal(other, &object); err != nil {
		t.Fatal(err)
	}
	object["address"] = identity.Signer.Hex()
	forged, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, forged, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openKeystoreSigner(path, accounts.Account{Address: identity.Signer}, []byte("payload"), func() ([]byte, error) { return []byte("public test password"), nil }); err == nil {
		t.Fatal("key metadata substituted for actual signer identity")
	}
}

func TestSigningPreflightClosesOnFailure(t *testing.T) {
	for _, mode := range []string{"reservation_write", "callback_error", "callback_panic"} {
		t.Run(mode, func(t *testing.T) {
			identity, block, encoded, _ := signingFixture(t)
			journal, err := CreateSigningJournal(filepath.Join(t.TempDir(), "journal"), identity)
			if err != nil {
				t.Fatal(err)
			}
			defer journal.Close()
			closed := false
			func() {
				defer func() {
					if value := recover(); value != nil && mode != "callback_panic" {
						t.Fatal(value)
					}
				}()
				_, err = journal.signWithPreflight(block, encoded, func(accounts.Account, []byte) (*signingSession, error) {
					if mode == "reservation_write" {
						journal.db.Close()
					}
					return &signingSession{close: func() { closed = true }, sign: func(accounts.Account, string, []byte) ([]byte, error) {
						if mode == "callback_panic" {
							panic("synthetic disconnect")
						}
						return nil, errors.New("synthetic disconnect")
					}}, nil
				})
				if !errors.Is(err, ErrSigningUncertain) {
					t.Fatalf("failed attempt not uncertain: %v", err)
				}
			}()
			if !closed {
				t.Fatal("key session was not closed after failure")
			}
		})
	}
}

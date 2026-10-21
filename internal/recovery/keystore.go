package recovery

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/accounts/keystore"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/crypto"
)

type signingSession struct {
	sign  datong.SignerFn
	close func()
}

type signerPreflight func(accounts.Account, []byte) (*signingSession, error)

func fixedSigner(signer datong.SignerFn) signerPreflight {
	return func(accounts.Account, []byte) (*signingSession, error) {
		if signer == nil {
			return nil, fmt.Errorf("signer callback required")
		}
		return &signingSession{sign: signer, close: func() {}}, nil
	}
}

func SignApprovedKeystore(chainPath, journalPath string, data []byte, approvedSHA256 common.Hash, keyPath string, password func() ([]byte, error)) (*types.Block, error) {
	return signApprovedOffline(chainPath, journalPath, data, approvedSHA256, func(account accounts.Account, payload []byte) (*signingSession, error) {
		return openKeystoreSigner(keyPath, account, payload, password)
	})
}

func openKeystoreSigner(path string, account accounts.Account, payload []byte, password func() ([]byte, error)) (*signingSession, error) {
	if !filepath.IsAbs(path) || password == nil {
		return nil, fmt.Errorf("absolute encrypted key path and password reader required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	encrypted, err := checkedKeyCrypto(data, account.Address)
	if err != nil {
		return nil, err
	}
	secret, err := password()
	defer eraseBytes(secret)
	if err != nil {
		return nil, fmt.Errorf("password input failed")
	}
	if len(secret) > 4096 {
		return nil, fmt.Errorf("password exceeds 4096 bytes")
	}
	plain, err := keystore.DecryptDataV3(*encrypted, string(secret))
	defer eraseBytes(plain)
	if err != nil {
		return nil, fmt.Errorf("encrypted key could not be decrypted")
	}
	key, err := crypto.ToECDSA(plain)
	if err != nil {
		return nil, fmt.Errorf("invalid decrypted private scalar")
	}
	closed := false
	closeKey := func() {
		for i := range key.D.Bits() {
			key.D.Bits()[i] = 0
		}
		closed = true
	}
	if crypto.PubkeyToAddress(key.PublicKey) != account.Address {
		closeKey()
		return nil, fmt.Errorf("decrypted key does not match approved signer")
	}
	expected := common.CopyBytes(payload)
	used := false
	return &signingSession{close: closeKey, sign: func(request accounts.Account, mime string, message []byte) ([]byte, error) {
		if closed || used || request.Address != account.Address || mime != "" || !bytes.Equal(message, expected) {
			return nil, fmt.Errorf("key session permits only its one approved signing payload")
		}
		used = true
		return crypto.Sign(crypto.Keccak256(message), key)
	}}, nil
}

func checkedKeyCrypto(data []byte, signer common.Address) (*keystore.CryptoJSON, error) {
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("encrypted key exceeds one MiB")
	}
	var key struct {
		Version int
		Address string
		Crypto  keystore.CryptoJSON
	}
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("invalid encrypted key JSON")
	}
	if key.Version != 3 || !common.IsHexAddress(key.Address) || common.HexToAddress(key.Address) != signer || key.Crypto.Cipher != "aes-128-ctr" || key.Crypto.KDF != "scrypt" {
		return nil, fmt.Errorf("expected signer requires a version 3 AES-128-CTR/scrypt keystore")
	}
	n, nOK := key.Crypto.KDFParams["n"].(float64)
	r, rOK := key.Crypto.KDFParams["r"].(float64)
	p, pOK := key.Crypto.KDFParams["p"].(float64)
	dklen, dkOK := key.Crypto.KDFParams["dklen"].(float64)
	salt, saltOK := key.Crypto.KDFParams["salt"].(string)
	if !nOK || !rOK || !pOK || !dkOK || !saltOK || math.Trunc(n) != n || math.Trunc(p) != p || n < 2 || n > 262144 || int(n)&(int(n)-1) != 0 || r != 8 || p < 1 || p > 16 || n*p > 1048576 || dklen != 32 {
		return nil, fmt.Errorf("unsupported or excessive scrypt parameters")
	}
	for _, field := range []struct {
		value string
		size  int
	}{{salt, 32}, {key.Crypto.CipherText, 32}, {key.Crypto.MAC, 32}, {key.Crypto.CipherParams.IV, 16}} {
		decoded, err := hex.DecodeString(field.value)
		if err != nil || len(decoded) != field.size {
			return nil, fmt.Errorf("invalid encrypted key field length")
		}
	}
	return &key.Crypto, nil
}

func eraseBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

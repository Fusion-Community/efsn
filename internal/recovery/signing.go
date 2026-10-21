package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/FusionFoundation/efsn/v5/accounts"
	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/rlp"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

var (
	ErrSigningUncertain = errors.New("signing reservation is unfinished; do not sign again")
	ErrSigningConflict  = errors.New("another payload is reserved for this parent")
)

type SigningIdentity struct {
	GenesisHash common.Hash
	ChainID     uint64
	Signer      common.Address
}

type signingRecord struct {
	Unsigned  []byte
	Signature []byte
}

type SigningJournal struct {
	mu       sync.Mutex
	db       *leveldb.DB
	identity SigningIdentity
	policy   *SigningPolicy
	fault    error
}

// CreateSigningJournal is an explicit, one-time initialization, never a recovery
// action. Copies, rollbacks and other signers using the same key are not protected.
func CreateSigningJournal(path string, identity SigningIdentity) (*SigningJournal, error) {
	return openSigningJournal(path, identity, true, nil)
}

func OpenSigningJournal(path string, identity SigningIdentity) (*SigningJournal, error) {
	return openSigningJournal(path, identity, false, nil)
}

func openSigningJournal(path string, identity SigningIdentity, create bool, policy *SigningPolicy) (*SigningJournal, error) {
	if !filepath.IsAbs(path) || identity.GenesisHash == (common.Hash{}) || identity.ChainID == 0 || identity.Signer == (common.Address{}) {
		return nil, fmt.Errorf("absolute journal path and explicit signing identity required")
	}
	db, err := leveldb.OpenFile(path, &opt.Options{ErrorIfExist: create, ErrorIfMissing: !create, Strict: opt.StrictAll})
	if err != nil {
		return nil, err
	}
	j := &SigningJournal{db: db, identity: identity}
	encoded, err := rlp.EncodeToBytes(identity)
	if err == nil && create {
		batch := new(leveldb.Batch)
		batch.Put([]byte("identity-v1"), encoded)
		if policy != nil {
			var data []byte
			data, err = rlp.EncodeToBytes(policy)
			if err == nil {
				batch.Put([]byte("policy-v1"), data)
			}
		}
		if err == nil {
			err = db.Write(batch, &opt.WriteOptions{Sync: true})
		}
	}
	if err == nil {
		err = j.readPolicy()
	}
	if err == nil {
		var stored []byte
		stored, err = db.Get([]byte("identity-v1"), nil)
		if err == nil && !bytes.Equal(stored, encoded) {
			err = fmt.Errorf("signing journal identity mismatch")
		}
	}
	if err == nil {
		err = j.validateRecords()
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return j, nil
}

func (j *SigningJournal) validateRecords() error {
	iterator := j.db.NewIterator(nil, nil)
	defer iterator.Release()
	for iterator.Next() {
		key := iterator.Key()
		if bytes.Equal(key, []byte("identity-v1")) || bytes.Equal(key, []byte("policy-v1")) {
			continue
		}
		if len(key) != 33 || key[0] != 'p' {
			return fmt.Errorf("unknown signing journal record")
		}
		if _, _, err := j.decodeRecord(common.BytesToHash(key[1:]), iterator.Value()); err != nil {
			return err
		}
	}
	if err := iterator.Error(); err != nil {
		return err
	}
	return j.checkPolicySequence(nil)
}

// Sign rebuilds an explicitly reviewed candidate against a stopped chain reader.
// It never imports or broadcasts. The callback must sign Keccak256(payload), as
// DaTong's ordinary SignerFn does. An ambiguous attempt permanently reserves its
// parent; recovery must not recreate the journal or call another signing path.
func (j *SigningJournal) Sign(chain Chain, plan Plan, txs types.Transactions, reviewed []byte, signer datong.SignerFn) (*types.Block, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.policy != nil {
		return nil, fmt.Errorf("policy journal requires approved offline signing")
	}
	return j.signReviewed(chain, plan, txs, reviewed, signer)
}

func (j *SigningJournal) signReviewed(chain Chain, plan Plan, txs types.Transactions, reviewed []byte, signer datong.SignerFn) (*types.Block, error) {
	return j.signReviewedWithPreflight(chain, plan, txs, reviewed, fixedSigner(signer))
}

func (j *SigningJournal) signReviewedWithPreflight(chain Chain, plan Plan, txs types.Transactions, reviewed []byte, open signerPreflight) (*types.Block, error) {
	if j.fault != nil {
		return nil, j.fault
	}
	if j.identity != (SigningIdentity{GenesisHash: plan.GenesisHash, ChainID: plan.ChainID, Signer: plan.Signer}) {
		return nil, fmt.Errorf("plan differs from journal signing identity")
	}
	block, err := reviewedCandidate(chain, plan, txs, reviewed)
	if err != nil {
		return nil, err
	}
	return j.signWithPreflight(block, reviewed, open)
}

func reviewedCandidate(chain Chain, plan Plan, txs types.Transactions, reviewed []byte) (*types.Block, error) {
	candidate, err := Build(chain, plan, txs)
	if err != nil {
		return nil, err
	}
	encoded, err := rlp.EncodeToBytes(candidate.Block)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(encoded, reviewed) {
		return nil, fmt.Errorf("rebuilt block differs from reviewed unsigned artifact")
	}
	return candidate.Block, nil
}

func (j *SigningJournal) signBlock(block *types.Block, encoded []byte, signer datong.SignerFn) (*types.Block, error) {
	return j.signWithPreflight(block, encoded, fixedSigner(signer))
}

func (j *SigningJournal) signWithPreflight(block *types.Block, encoded []byte, open signerPreflight) (*types.Block, error) {
	if err := j.checkPolicySequence(block); err != nil {
		return nil, err
	}
	key := append([]byte{'p'}, block.ParentHash().Bytes()...)
	stored, err := j.db.Get(key, nil)
	if err == nil {
		record, sealed, err := j.decodeRecord(block.ParentHash(), stored)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(record.Unsigned, encoded) {
			return nil, ErrSigningConflict
		}
		if sealed == nil {
			return nil, ErrSigningUncertain
		}
		return sealed, nil
	}
	if err != leveldb.ErrNotFound {
		return nil, err
	}
	payload, err := datong.SigningPayload(block.Header())
	if err != nil {
		return nil, err
	}
	session, err := open(accounts.Account{Address: j.identity.Signer}, common.CopyBytes(payload))
	if err != nil {
		return nil, err
	}
	defer session.close()
	record := signingRecord{Unsigned: encoded}
	if err := j.writeRecord(key, record); err != nil {
		return nil, err
	}
	signature, err := session.sign(accounts.Account{Address: j.identity.Signer}, "", payload)
	if err != nil {
		return nil, fmt.Errorf("%w: callback failed: %v", ErrSigningUncertain, err)
	}
	record.Signature = common.CopyBytes(signature)
	sealed, err := sealRecordedBlock(block, record.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningUncertain, err)
	}
	if err := j.writeRecord(key, record); err != nil {
		return nil, err
	}
	return sealed, nil
}

func (j *SigningJournal) writeRecord(key []byte, record signingRecord) error {
	data, err := rlp.EncodeToBytes(record)
	if err == nil {
		err = j.db.Put(key, data, &opt.WriteOptions{Sync: true})
	}
	if err != nil {
		j.fault = fmt.Errorf("%w: journal write failed: %v", ErrSigningUncertain, err)
	}
	return j.fault
}

func (j *SigningJournal) decodeRecord(parent common.Hash, data []byte) (signingRecord, *types.Block, error) {
	var record signingRecord
	if err := rlp.DecodeBytes(data, &record); err != nil {
		return record, nil, err
	}
	var block types.Block
	if err := rlp.DecodeBytes(record.Unsigned, &block); err != nil {
		return record, nil, err
	}
	header := block.Header()
	if _, err := datong.SigningPayload(header); err != nil {
		return record, nil, err
	}
	if block.ParentHash() != parent || block.Coinbase() != j.identity.Signer || block.NumberU64() == 0 || !bytes.Equal(header.Extra[len(header.Extra)-65:], make([]byte, 65)) {
		return record, nil, fmt.Errorf("invalid unsigned signing journal record")
	}
	if len(record.Signature) == 0 {
		return record, nil, nil
	}
	sealed, err := sealRecordedBlock(&block, record.Signature)
	return record, sealed, err
}

func sealRecordedBlock(block *types.Block, signature []byte) (*types.Block, error) {
	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid block signature length")
	}
	header := block.Header()
	copy(header.Extra[len(header.Extra)-65:], signature)
	if err := datong.VerifySignature(header); err != nil {
		return nil, err
	}
	return block.WithSeal(header), nil
}

// Saved returns the exact completed artifact even after the chain head advances.
// Retrieval is not approval to publish it; independently validate before import.
func (j *SigningJournal) Saved(parent common.Hash) (*types.Block, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.fault != nil {
		return nil, j.fault
	}
	data, err := j.db.Get(append([]byte{'p'}, parent.Bytes()...), nil)
	if err != nil {
		return nil, err
	}
	_, block, err := j.decodeRecord(parent, data)
	if err == nil && block == nil {
		err = ErrSigningUncertain
	}
	return block, err
}

func (j *SigningJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.fault = fmt.Errorf("signing journal is closed")
	return j.db.Close()
}

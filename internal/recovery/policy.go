package recovery

import (
	"fmt"
	"sort"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/rlp"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

type SigningPolicy struct {
	FirstParent       common.Hash
	FirstParentNumber uint64
	PurchaseOwner     common.Address
	BlockCount        uint64
	ExecutableSHA256  common.Hash
	ConfigSHA256      common.Hash
}

func CreateApprovedSigningJournal(path string, identity SigningIdentity, policy SigningPolicy) (*SigningJournal, error) {
	if err := validateSigningPolicy(identity, policy); err != nil {
		return nil, err
	}
	return openSigningJournal(path, identity, true, &policy)
}

func validateSigningPolicy(identity SigningIdentity, policy SigningPolicy) error {
	if policy.FirstParent == (common.Hash{}) || policy.PurchaseOwner == (common.Address{}) || policy.ExecutableSHA256 == (common.Hash{}) || policy.ConfigSHA256 == (common.Hash{}) {
		return fmt.Errorf("explicit parent, purchaser, executable and configuration pins required")
	}
	if policy.BlockCount != 1 && policy.BlockCount != 2 || policy.FirstParentNumber > ^uint64(0)-policy.BlockCount {
		return fmt.Errorf("policy must allow one backup block or two donation blocks without height overflow")
	}
	if (policy.BlockCount == 1) == (policy.PurchaseOwner == identity.Signer) {
		return fmt.Errorf("backup must purchase for donation owner; donation must purchase for itself")
	}
	return nil
}

func (j *SigningJournal) readPolicy() error {
	data, err := j.db.Get([]byte("policy-v1"), nil)
	if err == leveldb.ErrNotFound {
		return nil
	}
	if err != nil {
		return err
	}
	var policy SigningPolicy
	if err := rlp.DecodeBytes(data, &policy); err != nil {
		return err
	}
	if err := validateSigningPolicy(j.identity, policy); err != nil {
		return err
	}
	j.policy = &policy
	return nil
}

func (j *SigningJournal) checkPolicySequence(candidate *types.Block) error {
	if j.policy == nil {
		return nil
	}
	blocks := make([]*types.Block, 0, j.policy.BlockCount)
	sealed := make(map[common.Hash]*types.Block)
	iterator := j.db.NewIterator(util.BytesPrefix([]byte{'p'}), nil)
	defer iterator.Release()
	for iterator.Next() {
		if len(iterator.Key()) != 33 {
			continue
		}
		record, signed, err := j.decodeRecord(common.BytesToHash(iterator.Key()[1:]), iterator.Value())
		if err != nil {
			return err
		}
		var block types.Block
		if err := rlp.DecodeBytes(record.Unsigned, &block); err != nil {
			return err
		}
		blocks = append(blocks, &block)
		sealed[block.ParentHash()] = signed
	}
	if err := iterator.Error(); err != nil {
		return err
	}
	if candidate != nil {
		if _, exists := sealed[candidate.ParentHash()]; !exists {
			blocks = append(blocks, candidate)
		}
	}
	if uint64(len(blocks)) > j.policy.BlockCount {
		return fmt.Errorf("approved block quota exhausted")
	}
	sort.Slice(blocks, func(i, k int) bool { return blocks[i].NumberU64() < blocks[k].NumberU64() })
	parent, number := j.policy.FirstParent, j.policy.FirstParentNumber
	for index, block := range blocks {
		if !block.Number().IsUint64() || block.ParentHash() != parent || block.NumberU64() != number+1 {
			return fmt.Errorf("block is outside approved consecutive handover sequence")
		}
		completed := sealed[block.ParentHash()]
		if completed == nil {
			if index != len(blocks)-1 {
				return ErrSigningUncertain
			}
			break
		}
		parent, number = completed.Hash(), completed.NumberU64()
	}
	return nil
}

package recovery

import (
	"fmt"

	"github.com/FusionFoundation/efsn/v5/common"
	"github.com/FusionFoundation/efsn/v5/consensus"
	"github.com/FusionFoundation/efsn/v5/consensus/datong"
	"github.com/FusionFoundation/efsn/v5/core/rawdb"
	"github.com/FusionFoundation/efsn/v5/core/state"
	"github.com/FusionFoundation/efsn/v5/core/types"
	"github.com/FusionFoundation/efsn/v5/ethdb"
	"github.com/FusionFoundation/efsn/v5/params"
)

type Reader struct {
	db     ethdb.Database
	config *params.ChainConfig
	cache  state.Database
	engine *datong.DaTong
	head   *types.Header
}

// NewReader reads a stopped database without startup repair or canonical writes.
// The caller must open the database read-only and keep it open for the reader.
func NewReader(db ethdb.Database) (*Reader, error) {
	config := rawdb.ReadChainConfig(db, rawdb.ReadCanonicalHash(db, 0))
	if config == nil || config.DaTong == nil {
		return nil, fmt.Errorf("missing DaTong chain configuration")
	}
	hash := rawdb.ReadHeadBlockHash(db)
	number := rawdb.ReadHeaderNumber(db, hash)
	if number == nil || hash != rawdb.ReadHeadHeaderHash(db) || hash != rawdb.ReadHeadFastBlockHash(db) || hash != rawdb.ReadCanonicalHash(db, *number) {
		return nil, fmt.Errorf("full, header, fast and canonical heads must agree")
	}
	head := rawdb.ReadHeader(db, hash, *number)
	if head == nil {
		return nil, fmt.Errorf("missing head header")
	}
	cache := state.NewDatabase(db)
	engine := datong.New(config.DaTong, db)
	engine.SetStateCache(cache)
	return &Reader{db: db, config: config, cache: cache, engine: engine, head: head}, nil
}

func (r *Reader) Config() *params.ChainConfig  { return r.config }
func (r *Reader) Engine() consensus.Engine     { return r.engine }
func (r *Reader) CurrentHeader() *types.Header { return types.CopyHeader(r.head) }
func (r *Reader) StateAt(root, tickets common.Hash) (*state.StateDB, error) {
	return state.New(root, tickets, r.cache)
}
func (r *Reader) GetHeader(hash common.Hash, number uint64) *types.Header {
	return rawdb.ReadHeader(r.db, hash, number)
}
func (r *Reader) GetHeaderByNumber(number uint64) *types.Header {
	return r.GetHeader(rawdb.ReadCanonicalHash(r.db, number), number)
}
func (r *Reader) GetHeaderByHash(hash common.Hash) *types.Header {
	number := rawdb.ReadHeaderNumber(r.db, hash)
	if number == nil {
		return nil
	}
	return r.GetHeader(hash, *number)
}
func (r *Reader) GetBlock(hash common.Hash, number uint64) *types.Block {
	return rawdb.ReadBlock(r.db, hash, number)
}

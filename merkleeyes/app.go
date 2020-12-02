package merkleeyes

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"

	gogotypes "github.com/gogo/protobuf/types"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto/ed25519"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/protoio"
	"github.com/tendermint/tendermint/version"
	dbm "github.com/tendermint/tm-db"
)

const (
	// Transaction type bytes
	TxTypeSet           byte = 0x01
	TxTypeRm            byte = 0x02
	TxTypeGet           byte = 0x03
	TxTypeCompareAndSet byte = 0x04
	TxTypeValSetChange  byte = 0x05
	TxTypeValSetRead    byte = 0x06
	TxTypeValSetCAS     byte = 0x07

	NonceLength = 12

	// Additional error codes.
	CodeTypeUnknownRequest        = 2
	CodeTypeEncodingError         = 3
	CodeTypeBadNonce              = 4
	CodeTypeErrUnknownRequest     = 5
	CodeTypeInternalError         = 6
	CodeTypeErrBaseUnknownAddress = 7
	CodeTypeErrUnauthorized       = 8
)

// App is a Merkle KV-store served as an ABCI app.
type App struct {
	abci.BaseApplication

	db      dbm.DB
	state   *State
	changes []abci.ValidatorUpdate
	logger  log.Logger
}

var _ abci.Application = (*App)(nil)

// New initializes the database, loads any existing state, and returns a new
// App.
func New(dbDir string, treeCacheSize int) (*App, error) {
	const dbName = "merkleeyes"

	// Initialize a db.
	db, err := dbm.NewGoLevelDB(dbName, dbDir)
	if err != nil {
		return nil, fmt.Errorf("create db: %w", err)
	}

	// Initialize a state.
	state, err := NewState(db, treeCacheSize)
	if err != nil {
		return nil, fmt.Errorf("create state: %w", err)
	}

	return &App{
		state:   state,
		db:      db,
		changes: make([]abci.ValidatorUpdate, 0),
	}, nil
}

// SetLogger sets a logger.
func (app *App) SetLogger(l log.Logger) {
	app.logger = l
}

// CloseDB closes the database.
func (app *App) CloseDB() {
	app.db.Close()
}

// Info implements ABCI.
func (app *App) Info(req abci.RequestInfo) abci.ResponseInfo {
	return abci.ResponseInfo{
		Version:          version.ABCIVersion,
		AppVersion:       1,
		LastBlockHeight:  app.state.Height,
		LastBlockAppHash: app.state.Hash(),
	}
}

// InitChain implements ABCI.
func (app *App) InitChain(req abci.RequestInitChain) abci.ResponseInitChain {
	for _, v := range req.Validators {
		app.state.Validators.Set(&Validator{PubKey: ed25519.PubKey(v.PubKey.GetEd25519()), Power: v.Power})
	}

	return abci.ResponseInitChain{
		AppHash: app.state.Hash(),
	}
}

// CheckTx implements ABCI.
func (app *App) CheckTx(req abci.RequestCheckTx) abci.ResponseCheckTx {
	if len(req.Tx) < minTxLen() {
		return abci.ResponseCheckTx{
			Code: CodeTypeEncodingError,
			Log:  fmt.Sprintf("Tx length must be at least %d", minTxLen()),
		}
	}

	return abci.ResponseCheckTx{Code: abci.CodeTypeOK}
}

// DeliverTx implements ABCI.
func (app *App) DeliverTx(req abci.RequestDeliverTx) abci.ResponseDeliverTx {
	return app.doTx(req.Tx)
}

// BeginBlock implements ABCI.
func (app *App) BeginBlock(req abci.RequestBeginBlock) abci.ResponseBeginBlock {
	// reset valset changes
	app.changes = make([]abci.ValidatorUpdate, 0)
	return abci.ResponseBeginBlock{}
}

// EndBlock implements ABCI.
func (app *App) EndBlock(req abci.RequestEndBlock) abci.ResponseEndBlock {
	if len(app.changes) > 0 {
		app.state.Validators.Version++
	}
	return abci.ResponseEndBlock{ValidatorUpdates: app.changes}
}

// Commit implements abci.Application
func (app *App) Commit() abci.ResponseCommit {
	err := app.state.Commit(app.db)
	if err != nil {
		panic(err)
	}

	// if app.state.Committed.Size() == 0 {
	// 	return abci.ResponseCommit{Data: nil}
	// }
	return abci.ResponseCommit{Data: app.state.Hash()}
}

// Query implements ABCI.
func (app *App) Query(req abci.RequestQuery) (res abci.ResponseQuery) {
	tree := app.state.Committed

	if req.Height != 0 {
		res.Code = CodeTypeInternalError
		res.Log = "merkleeyes only supports queries on latest commit"
		return
	}

	res.Height = app.state.Height

	switch req.Path {

	case "/store", "/key": // Get by key
		key := req.Data // Data holds the key bytes
		res.Key = key
		if req.Prove {
			res.Code = CodeTypeInternalError
			res.Log = "Query with proof is not supported"
		} else {
			index, value := tree.Get(storeKey(key))
			if value == nil {
				res.Code = CodeTypeErrBaseUnknownAddress
				res.Log = "not found"
				return
			}
			res.Value = value
			res.Index = int64(index)
		}

	case "/index": // Get by Index
		index, n := binary.Varint(req.Data)
		if n != len(req.Data) {
			res.Code = CodeTypeEncodingError
			res.Log = "Varint did not consume all of in"
			return
		}

		key, value := tree.GetByIndex(index)
		if value == nil {
			res.Code = CodeTypeErrBaseUnknownAddress
			res.Log = "not found"
			return
		}
		res.Key = key
		res.Index = int64(index)
		res.Value = value

	case "/size": // Get size
		buf := make([]byte, binary.MaxVarintLen64)
		n := binary.PutVarint(buf, tree.Size())
		res.Value = buf[:n]

	default:
		res.Code = CodeTypeUnknownRequest
		res.Log = fmt.Sprintf("Unexpected Query path: %v", req.Path)
	}

	return
}

func nonceKey(nonce []byte) []byte {
	return append([]byte("/nonce/"), nonce...)
}

func storeKey(key []byte) []byte {
	return append([]byte("/key/"), key...)
}

func (app *App) doTx(tx []byte) abci.ResponseDeliverTx {
	if len(tx) < minTxLen() {
		return abci.ResponseDeliverTx{
			Code: CodeTypeEncodingError,
			Log:  fmt.Sprintf("Tx length must be at least %d", minTxLen()),
		}
	}

	var (
		tree  = app.state.Working
		nonce = tx[:NonceLength]
	)
	tx = tx[NonceLength:]

	// 1) Check nonce
	_, n := tree.Get(nonceKey(nonce))
	if n == nil {
		return abci.ResponseDeliverTx{
			Code: CodeTypeBadNonce,
			Log:  fmt.Sprintf("Nonce %X already exists", nonce),
		}
	}
	// mark nonce as processed
	updated := tree.Set(nonceKey(nonce), []byte{0x01})
	if !updated {
		return abci.ResponseDeliverTx{
			Code: CodeTypeInternalError,
			Log:  fmt.Sprintf("Can't mark nonce %X as processed", nonce),
		}
	}

	typeByte := tx[0]
	tx = tx[1:]

	// 2) Execute tx based on type
	switch typeByte {
	case TxTypeSet:
		key, errResp := unmarshalBytes(tx, "key", false)
		if key == nil {
			return errResp
		}

		value, errResp := unmarshalBytes(tx[len(key):], "value", true)
		if value == nil {
			return errResp
		}

		updated := tree.Set(storeKey(key), value)
		if !updated {
			return abci.ResponseDeliverTx{
				Code: CodeTypeInternalError,
				Log:  fmt.Sprintf("Failed to set %X to %X", key, value),
			}
		}

		app.logger.Info("SET", fmt.Sprintf("%X", key), fmt.Sprintf("%X", value))
		return abci.ResponseDeliverTx{Code: abci.CodeTypeOK}

	case TxTypeRm:
		key, errResp := unmarshalBytes(tx, "key", true)
		if key == nil {
			return errResp
		}

		_, removed := tree.Remove(storeKey(key))
		if !removed {
			return abci.ResponseDeliverTx{
				Code: CodeTypeInternalError,
				Log:  fmt.Sprintf("Failed to remove %X", key),
			}
		}

		app.logger.Info("RM", fmt.Sprintf("%X", key))
		return abci.ResponseDeliverTx{Code: abci.CodeTypeOK}

	case TxTypeGet:
		key, errResp := unmarshalBytes(tx, "key", true)
		if key == nil {
			return errResp
		}

		_, value := tree.Get(storeKey(key))
		if value == nil {
			return abci.ResponseDeliverTx{Code: CodeTypeErrBaseUnknownAddress,
				Log: fmt.Sprintf("Cannot find key: %X", key)}
		}

		app.logger.Info("GET", fmt.Sprintf("%X", key), fmt.Sprintf("%X", value))
		return abci.ResponseDeliverTx{Code: abci.CodeTypeOK, Data: value}

	case TxTypeCompareAndSet:
		key, errResp := unmarshalBytes(tx, "key", false)
		if key == nil {
			return errResp
		}

		compareValue, errResp := unmarshalBytes(tx[len(key):], "compareKey", false)
		if compareValue == nil {
			return errResp
		}

		setValue, errResp := unmarshalBytes(tx[len(key)+len(compareValue):], "setValue", true)
		if setValue == nil {
			return errResp
		}

		_, value := tree.Get(storeKey(key))
		if value == nil {
			return abci.ResponseDeliverTx{
				Code: CodeTypeErrBaseUnknownAddress,
				Log:  fmt.Sprintf("Cannot find key: %X", key),
			}
		}

		if !bytes.Equal(value, compareValue) {
			return abci.ResponseDeliverTx{
				Code: CodeTypeErrUnauthorized,
				Log:  fmt.Sprintf("Value was %X, not %X", value, compareValue),
			}
		}

		updated := tree.Set(storeKey(key), setValue)
		if !updated {
			return abci.ResponseDeliverTx{
				Code: CodeTypeInternalError,
				Log:  fmt.Sprintf("Failed to set %X to %X", key, setValue),
			}
		}

		app.logger.Info("CAS-SET", fmt.Sprintf("%X", key), fmt.Sprintf("%X", compareValue), fmt.Sprintf("%X", setValue))
		return abci.ResponseDeliverTx{Code: abci.CodeTypeOK}

	case TxTypeValSetChange:
		pubKey, errResp := unmarshalBytes(tx, "pubKey", false)
		if pubKey == nil {
			return errResp
		}

		if len(pubKey) != ed25519.PubKeySize {
			return abci.ResponseDeliverTx{
				Code: CodeTypeEncodingError,
				Log:  fmt.Sprintf("PubKey must be %d bytes: %X is %d bytes", ed25519.PubKeySize, pubKey, len(pubKey)),
			}
		}

		tx = tx[ed25519.PubKeySize:]
		// if len(tx) != 8 {
		// 	return abci.ResponseDeliverTx{Code: CodeTypeEncodingError,
		// 		Log: fmt.Sprintf("Power must be 8 bytes: %X is %d bytes", tx, len(tx))}
		// }

		power, n := binary.Uvarint(tx)
		if n != len(tx) {
			return abci.ResponseDeliverTx{
				Code: CodeTypeEncodingError,
				Log:  "Power must be uvarint",
			}
		}

		return app.updateValidator(pubKey, int64(power))

	case TxTypeValSetRead:
		bz, err := json.Marshal(app.state.Validators)
		if err != nil {
			return abci.ResponseDeliverTx{
				Code: CodeTypeInternalError,
				Log:  fmt.Sprintf("Marshaling error: %v", err),
			}
		}
		return abci.ResponseDeliverTx{Code: abci.CodeTypeOK, Data: bz, Log: string(bz)}

	case TxTypeValSetCAS:
		version, n := binary.Uvarint(tx)
		// if n != len(tx) {
		// 	return abci.ResponseDeliverTx{Code: CodeTypeEncodingError,
		// 		Log: "Power must be uvarint"}
		// }
		// if len(tx) < 8 {
		// 	return abci.ResponseDeliverTx{Code: CodeTypeEncodingError,
		// 		Log: fmt.Sprintf("Version number must be 8 bytes: remaining tx (%X) is %d bytes", tx, len(tx))}
		// }
		if app.state.Validators.Version != version {
			return abci.ResponseDeliverTx{
				Code: CodeTypeErrUnauthorized,
				Log:  fmt.Sprintf("Version was %d, not %d", app.state.Validators.Version, version),
			}
		}

		tx = tx[n:]

		pubKey, errResp := unmarshalBytes(tx, "pubKey", false)
		if pubKey == nil {
			return errResp
		}
		if len(pubKey) != ed25519.PubKeySize {
			return abci.ResponseDeliverTx{
				Code: CodeTypeEncodingError,
				Log:  fmt.Sprintf("PubKey must be %d bytes: %X is %d bytes", ed25519.PubKeySize, pubKey, len(pubKey)),
			}
		}

		tx = tx[ed25519.PubKeySize:]

		power, n := binary.Uvarint(tx)
		if n != len(tx) {
			return abci.ResponseDeliverTx{
				Code: CodeTypeEncodingError,
				Log:  "Power must be uvarint",
			}
		}

		return app.updateValidator(pubKey, int64(power))

	default:
		return abci.ResponseDeliverTx{
			Code: CodeTypeErrUnknownRequest,
			Log:  fmt.Sprintf("Unexpected tx type byte: %X", typeByte),
		}
	}
}

func (app *App) updateValidator(pubKey []byte, power int64) abci.ResponseDeliverTx {
	v := &Validator{PubKey: ed25519.PubKey(pubKey), Power: power}
	if v.Power == 0 {
		// remove validator
		if !app.state.Validators.Has(v) {
			return abci.ResponseDeliverTx{
				Code: CodeTypeErrUnauthorized,
				Log:  fmt.Sprintf("Cannot remove non-existent validator %v", v),
			}
		}
		app.state.Validators.Remove(v)
	} else {
		// add or update validator
		app.state.Validators.Set(v)
	}

	var pubKeyEd ed25519.PubKey
	copy(pubKeyEd[:], pubKey)
	pk, err := cryptoenc.PubKeyToProto(pubKeyEd)
	if err != nil {
		panic(err)
	}
	app.changes = append(app.changes, abci.ValidatorUpdate{PubKey: pk, Power: power})

	return abci.ResponseDeliverTx{Code: abci.CodeTypeOK}
}

func unmarshalBytes(buf []byte, key string, checkNoMoreBytes bool) ([]byte, abci.ResponseDeliverTx) {
	var bytes gogotypes.BytesValue
	err := protoio.UnmarshalDelimited(buf, &bytes)
	if err != nil {
		return nil, abci.ResponseDeliverTx{Code: CodeTypeEncodingError, Log: fmt.Sprintf("Error reading %s: %v", key, err)}
	}

	if checkNoMoreBytes {
		if len(buf) > len(bytes.Value) {
			return nil, abci.ResponseDeliverTx{Code: CodeTypeEncodingError, Log: "Got bytes left over"}
		}
	}

	return bytes.Value, abci.ResponseDeliverTx{}
}

// minimum length is 12 (nonce) + 1 (type byte) = 13
func minTxLen() int {
	return NonceLength + 1
}

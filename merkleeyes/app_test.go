package merkleeyes_test

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	abci "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/ed25519"
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	"github.com/tendermint/tendermint/libs/log"

	merkleeyes "github.com/melekes/jepsen/merkleeyes"
)

func TestMerkleEyesApp(t *testing.T) {
	app, err := merkleeyes.New(t.TempDir(), 0)
	require.NoError(t, err)
	app.SetLogger(log.TestingLogger())
	defer app.CloseDB()

	// Info
	res1 := app.Info(abci.RequestInfo{})
	assert.EqualValues(t, 0, res1.LastBlockHeight)
	assert.NotEmpty(t, res1.LastBlockAppHash)

	// InitChain
	assert.Len(t, app.ValidatorSetState().Validators, 0)
	privKey := ed25519.GenPrivKey()
	pubKey, err := cryptoenc.PubKeyToProto(privKey.PubKey())
	require.NoError(t, err)
	res2 := app.InitChain(abci.RequestInitChain{Validators: []abci.ValidatorUpdate{
		{PubKey: pubKey, Power: 1},
	}})
	assert.NotEmpty(t, res2.AppHash)
	assert.Len(t, app.ValidatorSetState().Validators, 1)

	// CheckTx
	res3 := app.CheckTx(abci.RequestCheckTx{Tx: []byte{}})
	assert.EqualValues(t, merkleeyes.CodeTypeEncodingError, res3.Code, res3.Log)
	res4 := app.CheckTx(abci.RequestCheckTx{Tx: readTx([]byte("foo"))})
	assert.Equal(t, abci.CodeTypeOK, res4.Code, res4.Log)

	// BeginBlock
	resBB := app.BeginBlock(abci.RequestBeginBlock{})
	assert.NotNil(t, resBB)

	// DeliverTx
	res5 := app.DeliverTx(abci.RequestDeliverTx{Tx: []byte{}})
	assert.EqualValues(t, merkleeyes.CodeTypeEncodingError, res5.Code, res5.Log)
	// get non-existing key
	res6 := app.DeliverTx(abci.RequestDeliverTx{Tx: readTx([]byte("foo"))})
	assert.EqualValues(t, int(merkleeyes.CodeTypeErrBaseUnknownAddress), res6.Code, res6.Log)
	// set
	res7 := app.DeliverTx(abci.RequestDeliverTx{Tx: setTx([]byte("foo"), []byte("bar"))})
	assert.Equal(t, abci.CodeTypeOK, res7.Code, res7.Log)
	// rm
	res8 := app.DeliverTx(abci.RequestDeliverTx{Tx: rmTx([]byte("baz"))})
	assert.EqualValues(t, merkleeyes.CodeTypeErrBaseUnknownAddress, res8.Code, res8.Log)
	// cas
	res9 := app.DeliverTx(abci.RequestDeliverTx{Tx: casTx([]byte("foo"), []byte("bar"), []byte("qux"))})
	assert.EqualValues(t, abci.CodeTypeOK, res9.Code, res9.Log)
	// valset change (add validator)
	res10 := app.DeliverTx(abci.RequestDeliverTx{Tx: valsetChangeTx(privKey.PubKey(), 10)})
	assert.EqualValues(t, abci.CodeTypeOK, res10.Code, res10.Log)
	// valset read
	res11 := app.DeliverTx(abci.RequestDeliverTx{Tx: valsetReadTx()})
	assert.EqualValues(t, abci.CodeTypeOK, res11.Code, res11.Log)
	assert.NotEmpty(t, res11.Data, res11.Log)
	// valset cas (change power)
	res12 := app.DeliverTx(abci.RequestDeliverTx{Tx: valsetCasTx(0, privKey.PubKey(), 11)})
	assert.EqualValues(t, abci.CodeTypeOK, res12.Code, res12.Log)

	// EndBlock
	resEB := app.EndBlock(abci.RequestEndBlock{})
	assert.Len(t, resEB.ValidatorUpdates, 1)

	// Commit
	resCommit := app.Commit()
	assert.NotEmpty(t, resCommit.Data)
	assert.NotEqual(t, resCommit.Data, res1.LastBlockAppHash)
}

func readTx(key []byte) []byte {
	nonce := make([]byte, merkleeyes.NonceLength)
	rand.Read(nonce)

	keyBz := encodeBytes(key)

	return append(append(nonce, merkleeyes.TxTypeGet), keyBz...)
}

func setTx(key, value []byte) []byte {
	nonce := make([]byte, merkleeyes.NonceLength)
	rand.Read(nonce)

	keyBz := encodeBytes(key)
	valueBz := encodeBytes(value)

	return append(append(append(nonce, merkleeyes.TxTypeSet), keyBz...), valueBz...)
}

func casTx(key, compareValue, newValue []byte) []byte {
	nonce := make([]byte, merkleeyes.NonceLength)
	rand.Read(nonce)

	keyBz := encodeBytes(key)
	compareValueBz := encodeBytes(compareValue)
	newValueBz := encodeBytes(newValue)

	return append(append(append(append(nonce, merkleeyes.TxTypeCompareAndSet), keyBz...), compareValueBz...), newValueBz...)
}

func rmTx(key []byte) []byte {
	nonce := make([]byte, merkleeyes.NonceLength)
	rand.Read(nonce)

	keyBz := encodeBytes(key)

	return append(append(nonce, merkleeyes.TxTypeRm), keyBz...)
}

func valsetChangeTx(pubKey crypto.PubKey, power int64) []byte {
	nonce := make([]byte, merkleeyes.NonceLength)
	rand.Read(nonce)

	pkBz := encodeBytes(pubKey.Bytes())
	powerBz := encodeUint64(uint64(power))

	return append(append(append(nonce, merkleeyes.TxTypeValSetChange), pkBz...), powerBz...)
}

func valsetReadTx() []byte {
	nonce := make([]byte, merkleeyes.NonceLength)
	rand.Read(nonce)

	return append(nonce, merkleeyes.TxTypeValSetRead)
}

func valsetCasTx(version uint64, pubKey crypto.PubKey, power int64) []byte {
	nonce := make([]byte, merkleeyes.NonceLength)
	rand.Read(nonce)

	versionBz := encodeUint64(version)
	pkBz := encodeBytes(pubKey.Bytes())
	powerBz := encodeUint64(uint64(power))

	return append(append(append(append(nonce, merkleeyes.TxTypeValSetCAS), versionBz...), pkBz...), powerBz...)
}

func encodeBytes(b []byte) []byte {
	// length prefix
	lenBz := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBz, uint64(len(b)))

	return append(lenBz, b...)
}

func encodeUint64(i uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	return b
}

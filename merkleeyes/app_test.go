package merkleeyes_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	abci "github.com/tendermint/tendermint/abci/types"
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

	// DeliverTx
	res5 := app.DeliverTx(abci.RequestDeliverTx{Tx: []byte{}})
	assert.EqualValues(t, merkleeyes.CodeTypeEncodingError, res5.Code, res5.Log)
	// get non-existing key
	res6 := app.DeliverTx(abci.RequestDeliverTx{Tx: readTx([]byte("foo"))})
	assert.EqualValues(t, int(merkleeyes.CodeTypeErrBaseUnknownAddress), res6.Code, res6.Log)
	// set
	res7 := app.DeliverTx(abci.RequestDeliverTx{Tx: setTx([]byte("foo"), []byte("bar"))})
	assert.Equal(t, abci.CodeTypeOK, res7.Code, res7.Log)

	// Commit
	resCommit := app.Commit()
	assert.NotEmpty(t, resCommit.Data)
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

func encodeBytes(b []byte) []byte {
	encLen := base64.StdEncoding.EncodedLen(len(b))

	lenBz := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBz, uint64(encLen))

	bz := make([]byte, encLen)
	base64.StdEncoding.Encode(bz, b)

	return append(lenBz, bz...)
}

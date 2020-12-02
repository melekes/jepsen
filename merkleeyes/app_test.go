package merkleeyes_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	merkleeyes "github.com/melekes/jepsen/merkleeyes"
	abci "github.com/tendermint/tendermint/abci/types"
)

func TestMerkleEyesApp(t *testing.T) {
	app, err := merkleeyes.New(t.TempDir(), 0)
	require.NoError(t, err)
	defer app.CloseDB()

	// Info
	res1 := app.Info(abci.RequestInfo{})
	assert.EqualValues(t, 0, res1.LastBlockHeight)
	assert.NotEmpty(t, res1.LastBlockAppHash)
}

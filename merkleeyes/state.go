package merkleeyes

import (
	"encoding/json"
	"fmt"

	"github.com/cosmos/iavl"
	"github.com/tendermint/tendermint/crypto/ed25519"
	dbm "github.com/tendermint/tm-db"
)

var stateKey = []byte("merkleeyes:state")

// State represents the app states, separating the commited state (for queries)
// from the working state (for CheckTx and DeliverTx).
//
// It contains the latest root hash and block height as well as the active validator set.
type State struct {
	Working   *iavl.MutableTree
	Committed *iavl.ImmutableTree

	Height     int64              `json:"height"`
	Validators *ValidatorSetState `json:"validators"`
}

// NewState returns a new State.
func NewState(db dbm.DB, treeCacheSize int) (*State, error) {
	// Initialize a tree.
	tree, err := iavl.NewMutableTree(db, treeCacheSize)
	if err != nil {
		return nil, fmt.Errorf("create tree: %w", err)
	}
	lastVersion, err := tree.Load()
	if err != nil {
		return nil, fmt.Errorf("load tree: %w", err)
	}

	// Get immutable version.
	if lastVersion == 0 {
		_, lastVersion, err = tree.SaveVersion()
		if err != nil {
			return nil, fmt.Errorf("save initial tree: %w", err)
		}
	}

	iTree, err := tree.GetImmutable(lastVersion)
	if err != nil {
		return nil, fmt.Errorf("get immutable tree: %w", err)
	}

	// Load the auxiliary state.
	auxState, err := loadAuxState(db)
	if err != nil {
		return nil, fmt.Errorf("load additional state: %w", err)
	}

	return &State{
		Working:   tree,
		Committed: iTree,

		Height:     auxState.Height,
		Validators: auxState.Validators,
	}, nil
}

// Commit saves Working version and updates Committed version.
func (s *State) Commit(db dbm.DB) error {
	_, version, err := s.Working.SaveVersion()
	if err != nil {
		return fmt.Errorf("save tree: %w", err)
	}

	iTree, err := s.Working.GetImmutable(version)
	if err != nil {
		return fmt.Errorf("get immutable tree: %w", err)
	}
	s.Committed = iTree

	// Increment height.
	s.Height++

	return saveAuxState(db, auxState{
		Height:     s.Height,
		Validators: s.Validators,
	})
}

// Hash returns the last committed hash.
func (s *State) Hash() []byte {
	return s.Committed.Hash()
}

///////////////////////////////////////////////////////////////////////////////

// An auxiliary state. The main state (keys and values) is stored in an iavl tree.
type auxState struct {
	Height     int64              `json:"height"`
	Validators *ValidatorSetState `json:"validators"`
}

func loadAuxState(db dbm.DB) (auxState, error) {
	// initial state
	s := auxState{
		Height:     0,
		Validators: &ValidatorSetState{},
	}

	bz, err := db.Get(stateKey)
	if err != nil {
		return s, fmt.Errorf("get state: %w", err)
	}

	if len(bz) != 0 {
		err = json.Unmarshal(bz, &s)
		if err != nil {
			return s, fmt.Errorf("unmarshal: %w", err)
		}
	}

	return s, nil
}

func saveAuxState(db dbm.DB, s auxState) error {
	bz, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	err = db.SetSync(stateKey, bz)
	if err != nil {
		return fmt.Errorf("set state: %w", err)
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////

// ValidatorSetState contains the validator set and its version (~ the number
// of times it was changed).
type ValidatorSetState struct {
	Version    uint64       `json:"version"`
	Validators []*Validator `json:"validators"`
}

// Validator represents a single validator.
type Validator struct {
	PubKey ed25519.PubKey `json:"pub_key"`
	Power  int64          `json:"power"`
}

// Has returns true if v is present in the validator set.
func (vss *ValidatorSetState) Has(v *Validator) bool {
	for _, v1 := range vss.Validators {
		if v1.PubKey.Equals(v.PubKey) {
			return true
		}
	}
	return false
}

// Remove removes v from the validator set.
func (vss *ValidatorSetState) Remove(v *Validator) {
	vals := make([]*Validator, 0, len(vss.Validators)-1)
	for _, v1 := range vss.Validators {
		if !v1.PubKey.Equals(v.PubKey) {
			vals = append(vals, v1)
		}
	}
	vss.Validators = vals
}

// Set updates v or adds v to the set.
func (vss *ValidatorSetState) Set(v *Validator) {
	for i, v1 := range vss.Validators {
		if v1.PubKey.Equals(v.PubKey) {
			vss.Validators[i] = v
			return
		}
	}
	vss.Validators = append(vss.Validators, v)
}

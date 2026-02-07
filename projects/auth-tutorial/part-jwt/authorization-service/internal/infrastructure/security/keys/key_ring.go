package keys

import (
	"errors"
	"sort"
)

type KeyRing struct {
	keys   map[string]*KeyPair
	active *KeyPair
}

func NewKeyRing(pairs []*KeyPair) (*KeyRing, error) {
	if len(pairs) == 0 {
		return nil, errors.New("no signing keys found")
	}

	keyMap := make(map[string]*KeyPair)
	for _, kp := range pairs {
		keyMap[kp.Kid] = kp
	}

	// Sort keys to determine the active one (e.g., latest by Kid)
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Kid > pairs[j].Kid
	})

	return &KeyRing{
		keys:   keyMap,
		active: pairs[0],
	}, nil
}

func (k *KeyRing) Active() *KeyPair {
	return k.active
}

func (k *KeyRing) All() []*KeyPair {
	list := make([]*KeyPair, 0, len(k.keys))
	for _, v := range k.keys {
		list = append(list, v)
	}
	return list
}

func (k *KeyRing) Get(kid string) (*KeyPair, bool) {
	kp, ok := k.keys[kid]
	return kp, ok
}

package lfcrypt

import "sync"

func NewStore() *Store {
	return &Store{
		keys: make(map[uint32]Cryptor),
	}
}

// Store contains a set of Cryptor instances to be used for decrypting a stream
type Store struct {
	mtx  sync.Mutex
	keys map[uint32]Cryptor
}

// AddKey adds a AEAD_AES_256_CBC_HMAC_SHA_512 based Cryptor to Store. (deprecated: use Store.Add())
func (ks *Store) AddKey(secret []byte) error {
	c, err := NewAES256SHA512(secret)
	if err != nil {
		return err
	}
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	ks.keys[c.KeyId()] = c
	return nil
}

// Add adds a Cryptor to the Store based on its KeyId
func (ks *Store) Add(c Cryptor) error {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	ks.keys[c.KeyId()] = c
	return nil
}

// ByKeyId returns a Cryptor instance based in the KeyID. Returns ErrNoMatchingKey when a key is not found by this ID.
func (ks *Store) ByKeyId(kid uint32) (Cryptor, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()

	if c, ok := ks.keys[kid]; ok {
		return c, nil
	}
	return nil, ErrNoMatchingKey
}

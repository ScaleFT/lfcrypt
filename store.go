package lfcrypt

import "sync"

func NewStore() *Store {
	return &Store{
		keys: make(map[uint32]Cryptor),
	}
}

type Store struct {
	mtx  sync.Mutex
	keys map[uint32]Cryptor
}

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

func (ks *Store) Add(c Cryptor) error {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()
	ks.keys[c.KeyId()] = c
	return nil
}

func (ks *Store) ByKeyId(kid uint32) (Cryptor, error) {
	ks.mtx.Lock()
	defer ks.mtx.Unlock()

	if c, ok := ks.keys[kid]; ok {
		return c, nil
	}
	return nil, ErrNoMatchingKey
}

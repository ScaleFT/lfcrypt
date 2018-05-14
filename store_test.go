package lfcrypt

import "testing"

func TestStore(t *testing.T) {
	s := NewStore()

	// legacy API
	s.AddKey(dummyKey)

	c2, err := NewAES256SHA512(dummyKey2)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	s.Add(c2)

	if len(s.keys) != 2 {
		t.Fatalf("Expected 2 keys in Store, found %d", len(s.keys))
	}

	_, err = s.ByKeyId(1)
	if err != ErrNoMatchingKey {
		t.Fatalf("Expected no such key error: %s", err)
	}

	c3, err := s.ByKeyId(c2.KeyId())
	if err != nil {
		t.Fatalf("Expected no error: %s", err)
	}

	if c3 != c2 {
		t.Fatalf("Expected same Cryptor instance")
	}

	dkId := ComputeKeyId(dummyKey)
	c4, err := s.ByKeyId(dkId)
	if err != nil {
		t.Fatalf("Expected no error: %s", err)
	}
	ec, ok := c4.(*aeadCryptor)
	if !ok {
		t.Fatalf("Expected *etmCryptor: %T", c4)
	}

	if ec.keyid != dkId {
		t.Fatalf("Expected *etmCryptor with matching keyid: %d != %d", ec.keyid, dkId)
	}
}

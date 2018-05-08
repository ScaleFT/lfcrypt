package lfcrypt

import (
	"encoding/hex"
	"testing"
)

func TestWriteNonce(t *testing.T) {
	stream := writeStream{
		nonce: make([]byte, 12),
	}
	nonces := map[string]bool{}
	for i := 0; i < 100; i++ {
		err := stream.refreshNonce(uint32(i % 10))
		if err != nil {
			t.Fatalf("refreshNonce returned error: %s", err)
		}
		n := hex.Dump(stream.nonce)
		if nonces[n] {
			t.Fatalf("repeated nonce: [%d]: %s", i, n)
		}
		nonces[n] = true
	}
}

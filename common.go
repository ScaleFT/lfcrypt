package lfcrypt

type keyId struct {
	KeyID uint32 `json:"key_id"`
}

const chunkSize = 65000
const headerStr = "lfcrypt0"
const maxUint16 = ^uint16(0)

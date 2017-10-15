package main

import (
	"fmt"
)

type StringCoding string

const (
	CODING_B64 = StringCoding("base64")
	CODING_HEX = StringCoding("hex")
)

///////////////////////////////////////////////////////////////////////

type KeyDerivationFunc string

const (
	PBKDF2 = "pbkdf2"

//	SCRIPT = "script"
)

///////////////////////////////////////////////////////////////////////

type CryptoKey struct {
	salt []byte
	key  []byte
}

func (c *CryptoKey) getSalt(coding StringCoding) string {
	return bytesToString(c.salt, coding)
}

func (c *CryptoKey) getKey(coding StringCoding) string {
	return bytesToString(c.key, coding)
}

func (c CryptoKey) String() string {
	return fmt.Sprintf("CryptoKey(salt=%v, key=%v", c.getSalt(CODING_B64), c.getKey(CODING_B64))
}

package main

import (
	b64 "encoding/base64"
	"fmt"
	"testing"
)

func TestAES(t *testing.T) {
	src := "This is test string"
	key := "MTExMTExMTExMTExMTExMQ=="
	key_b64, _ := b64.StdEncoding.DecodeString(key)

	coded, err := AESEncrypt(src, key_b64)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Crypted: %v\n", *coded)

	decoded, err := AESDecrypt(*coded, key_b64)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Decrypted: %v\n", *decoded)
}

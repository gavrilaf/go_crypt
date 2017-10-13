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

	fmt.Printf("Crypted: %v\n", coded)

	decoded, err := AESDecrypt(coded, key_b64)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Decrypted: %v\n", decoded)

	if src != decoded {
		t.Error("Decoding error!!!")
	}
}

func TestGenerateKey(t *testing.T) {
	psw := "Test password"

	key, err := generateKey(psw, PBKDF2)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("PBKDF2: %v\n", key)
	fmt.Printf("PBKDF2 (hex): %v, %v\n", key.getSalt(CODING_HEX), key.getKey(CODING_HEX))
}

func TestPBKDF2AndCrypt(t *testing.T) {
	psw := "Test password"
	src := "This is test string"

	key, err := generateKey(psw, PBKDF2)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Generated key: %v\n", key)

	coded, err := AESEncrypt(src, key.key)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Crypted: %v\n", coded)

	decoded, err := AESDecrypt(coded, key.key)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Decrypted: %v\n", decoded)

	if src != decoded {
		t.Error("Decoding error!!!")
	}
}

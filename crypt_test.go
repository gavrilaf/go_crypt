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

func TestGenerateAESKey(t *testing.T) {
	psw := "Test password"

	salt, err := generateSalt()
	if err != nil {
		t.Error(err)
	}

	key := generateAESKey(psw, salt)

	s_salt := b64.StdEncoding.EncodeToString(salt)
	s_key := b64.StdEncoding.EncodeToString(key)
	fmt.Printf("Generated salt: %v, key: %v\n", s_salt, s_key)
}

func TestGenerateKeyAndCrypt(t *testing.T) {
	psw := "Test password"
	src := "This is test string"

	salt, err := generateSalt()
	if err != nil {
		t.Error(err)
	}

	key := generateAESKey(psw, salt)

	s_key := b64.StdEncoding.EncodeToString(key)
	fmt.Printf("Generated key: %v\n", s_key)

	coded, err := AESEncrypt(src, key)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Crypted: %v\n", coded)

	decoded, err := AESDecrypt(coded, key)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Decrypted: %v\n", decoded)

	if src != decoded {
		t.Error("Decoding error!!!")
	}
}

package main

import (
	"fmt"
	"testing"
)

func TestCrypto(t *testing.T) {
	src := "This is test string"
	key := "MTExMTExMTExMTExMTExMQ=="

	fmt.Println("*** TestCrypto ***")

	encrypted, err := DoEncrypt(src, key, CODING_B64)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Encrypted: %v\n", encrypted)

	decrypted, err := DoDecrypt(encrypted, key, CODING_B64)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Decrypted: %v\n", decrypted)

	if src != decrypted {
		t.Error("Decoding error!!!")
	}
}

func TestGenerateKey(t *testing.T) {
	psw := "Test password"

	fmt.Println("*** TestGenerateKey ***")

	key, err := generateKey(psw, PBKDF2)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("PBKDF2: %v\n", key)
	fmt.Printf("PBKDF2 (hex): %v, %v\n", key.getSalt(CODING_HEX), key.getKey(CODING_HEX))
}

func TestPBKDF2AndCrypt(t *testing.T) {
	psw := "Test password"
	src := "This is a long test string! You are amazing!"

	fmt.Println("*** TestPBKDF2AndCrypt ***")

	key, err := generateKey(psw, PBKDF2)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Generated key: %v\n", key)

	encrypted, err := DoEncrypt(src, key.getKey(CODING_HEX), CODING_HEX)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Encrypted (hex): %v\n", encrypted)

	decrypted, err := DoDecrypt(encrypted, key.getKey(CODING_HEX), CODING_HEX)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Decrypted (hex): %v\n", decrypted)

	if src != decrypted {
		t.Error("Decoding error!!!")
	}

	encrypted, err = DoEncrypt(src, key.getKey(CODING_B64), CODING_B64)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Encrypted (base64): %v\n", encrypted)

	decrypted, err = DoDecrypt(encrypted, key.getKey(CODING_B64), CODING_B64)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("Decrypted (base64): %v\n", decrypted)

	if src != decrypted {
		t.Error("Decoding error!!!")
	}

}

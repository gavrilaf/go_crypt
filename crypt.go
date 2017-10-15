package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

func DoEncrypt(text string, key string, coding StringCoding) (string, error) {
	decoded_key, err := decodeString(key, coding)
	if err != nil {
		return "", fmt.Errorf("Can't decode key: %v", err)
	}

	ciphertext, err := AESEncrypt(text, decoded_key)
	if err != nil {
		return "", err
	}

	return bytesToString(ciphertext, coding), nil
}

func DoDecrypt(text string, key string, coding StringCoding) (string, error) {
	decoded_key, err := decodeString(key, coding)
	if err != nil {
		return "", fmt.Errorf("Can't decode key: %v", err)
	}

	buffer, err := decodeString(text, coding)
	if err != nil {
		return "", fmt.Errorf("Can't decode text: %v", err)
	}

	decrypted, err := AESDecrypt(buffer, decoded_key)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

/////////////////////////////////////////////////////////////////////////////////

func AESDecrypt(buffer []byte, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(buffer) == 0 || (len(buffer)%aes.BlockSize) != 0 {
		return nil, errors.New("invalid buffer length")
	}

	iv := buffer[:aes.BlockSize]
	msg := buffer[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	unpadMsg, err := Unpad(msg)
	if err != nil {
		return nil, err
	}

	return unpadMsg, nil
}

func AESEncrypt(text string, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	msg := Pad([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))

	return ciphertext, nil
}

/////////////////////////////////////////////////////////////////////////////////////

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

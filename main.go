package main

import (
	b64 "encoding/base64"

	"fmt"
	"github.com/gin-gonic/gin"

	"net/http"
	"strings"
)

const (
	VERSION = "1.0"
)

func main() {
	router := gin.Default()

	router.GET("/ping", Ping)

	v1 := router.Group("/crypto")
	{
		v1.POST("/encrypt", Encrypt)
		v1.POST("/decrypt", Decrypt)
	}

	router.Run()
}

func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"version": VERSION})
}

func Encrypt(c *gin.Context) {
	s := c.PostForm("string")
	key := c.PostForm("key")
	algo := c.PostForm("algo")

	res, err := DoEncrypt(s, key, strings.ToLower(algo))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "result": res})
}

func Decrypt(c *gin.Context) {
	s := c.PostForm("string")
	key := c.PostForm("key")
	algo := c.PostForm("algo")

	res, err := DoDecrypt(s, key, strings.ToLower(algo))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "result": res})
}

func DoEncrypt(data string, key string, algo string) (string, error) {
	decoded_key, err := b64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("Can't decode key: %v", err)
	}

	switch algo {
	case "aes":
		return AESEncrypt(data, decoded_key)
	default:
		return "", fmt.Errorf("Unknow algorithm: %v", algo)
	}
}

func DoDecrypt(data string, key string, algo string) (string, error) {
	decoded_key, err := b64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("Can't decode key: %v", err)
	}

	switch algo {
	case "aes":
		return AESDecrypt(data, decoded_key)
	default:
		return "", fmt.Errorf("Unknow algorithm: %v", algo)
	}
}

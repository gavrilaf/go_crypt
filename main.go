package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
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
		v1.POST("/generate_key", GenerateKey)
	}

	router.Run()
}

func Ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"version": VERSION})
}

func GenerateKey(c *gin.Context) {
	psw := c.PostForm("password")

	coding, err := getCoding(c.PostForm("coding"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	key, err := generateKey(psw, PBKDF2)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "salt": key.getSalt(coding), "key": key.getKey(coding)})
}

func Encrypt(c *gin.Context) {
	text := c.PostForm("text")
	key := c.PostForm("key")

	coding, err := getCoding(c.PostForm("coding"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	encrypted, err := DoEncrypt(text, key, coding)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "result": encrypted})
}

func Decrypt(c *gin.Context) {
	text := c.PostForm("text")
	key := c.PostForm("key")

	coding, err := getCoding(c.PostForm("coding"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	decrypted, err := DoDecrypt(text, key, coding)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "result": decrypted})
}

package main

import (
	b64 "encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

func getCoding(s string) (StringCoding, error) {
	switch strings.ToLower(s) {
	case "base64":
		return CODING_B64, nil
	case "hex":
		return CODING_HEX, nil
	default:
		return CODING_HEX, fmt.Errorf("Unknown coding: %v", s)
	}
}

func decodeString(s string, coding StringCoding) ([]byte, error) {
	switch coding {
	case CODING_HEX:
		return hex.DecodeString(s)
	default: // CODING_B64
		return b64.StdEncoding.DecodeString(s)
	}
}

func bytesToString(bt []byte, coding StringCoding) string {
	switch coding {
	case CODING_HEX:
		return hex.EncodeToString(bt)
	default: // CODING_B64
		return b64.StdEncoding.EncodeToString(bt)
	}
}

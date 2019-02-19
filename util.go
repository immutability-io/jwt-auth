package main

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

func hashKeccak256(data string) []byte {
	input := []byte(data)
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(input), input)
	hash := crypto.Keccak256([]byte(msg))
	return hash
}

func containsIgnoreCase(stringSlice []string, searchString string) bool {
	for _, value := range stringSlice {
		if strings.ToUpper(value) == strings.ToUpper(searchString) {
			return true
		}
	}
	return false
}

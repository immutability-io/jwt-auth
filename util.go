package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

func hashKeccak256(data string) []byte {
	input := []byte(data)
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(input), input)
	hash := crypto.Keccak256([]byte(msg))
	return hash
}

func contains(stringSlice []string, searchString string) bool {
	for _, value := range stringSlice {
		if value == searchString {
			return true
		}
	}
	return false
}

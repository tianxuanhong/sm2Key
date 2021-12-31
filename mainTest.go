package main

import (
	"fmt"
	"keyTest/key"
)

func main(){
	privateKey := key.GetPrivateKeySoft()
	keyBytes := key.BigintToBytes(privateKey.PublicKey)
	fmt.Println(privateKey)
	fmt.Println(keyBytes)
}


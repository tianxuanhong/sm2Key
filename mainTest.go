package main

import (
	"fmt"
	"keyTest/key"
)

func main(){
	privateKey := key.GetPrivateKeySoft()
	fmt.Printf("publicKey x: %0x \r\n",privateKey.PublicKey.X)
	fmt.Printf("publicKey y: %0x \r\n",privateKey.PublicKey.Y)
	keyBytes := key.BigintToBytes(privateKey.PublicKey)
	//fmt.Println(privateKey)
	//fmt.Println(keyBytes)
	keyGet := key.BytesToBigint(keyBytes)
	fmt.Printf("keyGet x : %0x \r\n",keyGet.X)
	fmt.Printf("keyGet y : %0x \r\n",keyGet.Y)
}


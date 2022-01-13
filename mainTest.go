package main

import (
	"encoding/hex"
	"fmt"
)

func main(){
	//privateKey := key.GetPrivateKeySoft()
	//fmt.Printf("publicKey x: %0x \r\n",privateKey.PublicKey.X)
	//fmt.Printf("publicKey y: %0x \r\n",privateKey.PublicKey.Y)
	//keyBytes := key.BigintToBytes(privateKey.PublicKey)
	////fmt.Println(privateKey)
	////fmt.Println(keyBytes)
	//keyGet := key.BytesToBigint(keyBytes)
	//fmt.Printf("keyGet x : %0x \r\n",keyGet.X)
	//fmt.Printf("keyGet y : %0x \r\n",keyGet.Y)

	hexTest()
}

func hexTest(){
	byte_data := []byte("ceshishuju")
	fmt.Printf("%0x \r\n","ceshishuju")
	data := hex.EncodeToString(byte_data)
	fmt.Println(data)
}
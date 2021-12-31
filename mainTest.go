package main

import (
	"fmt"
	"keyTest/key"
)

func main(){
	privateKey := key.GetPrivateKeySoft()
	fmt.Println(privateKey)
}


package key

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

//privateKey转换为[]byte
func BigintToBytes(key PublicKey)[]byte{
	var keyBytes []byte
	x := key.X.Bits()
	y := key.Y.Bits()
	fmt.Printf("x = %0x \n",x)
	fmt.Printf("y = %0x \n",y)
	for _,each := range x{
		KBytes := IntToBytes(int(each))
		keyBytes = append(keyBytes, KBytes...)
	}
	for _,each := range y{
		KBytes := IntToBytes(int(each))
		keyBytes = append(keyBytes, KBytes...)
	}
	fmt.Printf("key=%x",keyBytes)
	return keyBytes
}

//整形转换成字节
func IntToBytes(n int) []byte {
	x := int64(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}
//字节转换成整形
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x int32
	binary.Read(bytesBuffer, binary.BigEndian, &x)

	return int(x)
}

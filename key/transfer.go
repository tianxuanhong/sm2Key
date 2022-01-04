package key

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
)

//privateKey转换为[]byte xiaoduan
func BigintToBytesLittle(key PublicKey)[]byte{
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

//da duan
func BigintToBytes(key PublicKey)[]byte{
	var keyBytes []byte
	x := key.X.Bytes()
	y := key.Y.Bytes()
	keyBytes = append(keyBytes,x...)
	keyBytes = append(keyBytes,y...)
	return keyBytes
}

//da duan
func BytesToBigint(keyBytes []byte)(key PublicKey){
	l := len(keyBytes)
	x := keyBytes[:l/2]
	y := keyBytes[l/2:]

	xInt :=new(big.Int).SetBytes(x)
	yInt :=new(big.Int).SetBytes(y)
	key.X = xInt
	key.Y = yInt
	return
}

//整形转换成字节
func IntToBytes(n int) []byte {
	x := int64(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}
//字节转换成整形
func BytesToInt(b []byte) int64 {
	bytesBuffer := bytes.NewBuffer(b)
	var x int64
	binary.Read(bytesBuffer, binary.BigEndian, &x)

	return int64(x)
}

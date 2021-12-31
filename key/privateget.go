package key

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sync"
)

func GetPrivateKeySoft()*PrivateKey {
	path := "/opt/fabric/0aac9dd6aa0747ce9430453e4e6e3fe1/crypto-config/ordererOrganizations/org2.ex2.com/users/Admin@org2.ex2.com/msp/keystore/392297f73dbdff60fdcec9495fed5d51c2cb243ea8112560f22379f183ea3bb7_sk"
	rawKey, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
		return nil
	}

	block, _ := pem.Decode(rawKey)

	priv, err := KeyImport(block.Bytes)
	return priv
}

func KeyImport(raw interface{}) (k *PrivateKey, err error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[GMSM2PrivateKeyImportOpts] Invalid raw material. Expected byte array.")
	}
	gmsm2SK, err := ParsePKCS8UnecryptedPrivateKey(der)
	if err != nil {
		fmt.Println(err)
		return nil,err
	}

	return gmsm2SK, nil
}

var (
	oidSM2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)
func ParsePKCS8UnecryptedPrivateKey(der []byte) (*PrivateKey, error) {
	var privKey pkcs8

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(privKey.Algo.Algorithm, oidSM2) {
		return nil, errors.New("x509: not sm2 elliptic curve")
	}
	return ParseSm2PrivateKey(privKey.PrivateKey)
}

type sm2PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type sm2P256FieldElement [9]uint32
type sm2P256Curve struct {
	RInverse *big.Int
	*elliptic.CurveParams
	a, b, gx, gy sm2P256FieldElement
}


const (
	bottom28Bits = 0xFFFFFFF
	bottom29Bits = 0x1FFFFFFF
)
// X = a * R mod P
func sm2P256FromBig(X *sm2P256FieldElement, a *big.Int) {
	x := new(big.Int).Lsh(a, 257)
	x.Mod(x, sm2P256.P)
	for i := 0; i < 9; i++ {
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom29Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 29)
		i++
		if i == 9 {
			break
		}
		if bits := x.Bits(); len(bits) > 0 {
			X[i] = uint32(bits[0]) & bottom28Bits
		} else {
			X[i] = 0
		}
		x.Rsh(x, 28)
	}
}
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}
type PrivateKey struct {
	PublicKey
	D *big.Int
}
var initonce sync.Once
var sm2P256 sm2P256Curve
func initP256Sm2() {
	sm2P256.CurveParams = &elliptic.CurveParams{Name: "SM2-P-256"} // sm2
	A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	//SM2椭	椭 圆 曲 线 公 钥 密 码 算 法 推 荐 曲 线 参 数
	sm2P256.P, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2P256.N, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2P256.B, _ = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2P256.Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2P256.Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2P256.RInverse, _ = new(big.Int).SetString("7ffffffd80000002fffffffe000000017ffffffe800000037ffffffc80000002", 16)
	sm2P256.BitSize = 256
	sm2P256FromBig(&sm2P256.a, A)
	sm2P256FromBig(&sm2P256.gx, sm2P256.Gx)
	sm2P256FromBig(&sm2P256.gy, sm2P256.Gy)
	sm2P256FromBig(&sm2P256.b, sm2P256.B)
}
func P256Sm2() elliptic.Curve {
	initonce.Do(initP256Sm2)
	return sm2P256
}
func ParseSm2PrivateKey(der []byte) (*PrivateKey, error) {
	var privKey sm2PrivateKey

	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse SM2 private key: " + err.Error())
	}
	curve := P256Sm2()
	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(PrivateKey)
	priv.Curve = curve
	priv.D = k
	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)
	return priv, nil
}

func getPemMaterialFromDir(dir string) ([][]byte) {
	_, err := os.Stat(dir)
	if os.IsNotExist(err) {
		fmt.Println("error: ",err)
		return nil
	}

	content := make([][]byte, 0)
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		fmt.Println("error: ",err)
		return nil
	}

	for _, f := range files {
		fullName := filepath.Join(dir, f.Name())

		f, err := os.Stat(fullName)
		if err != nil {
			continue
		}
		if f.IsDir() {
			continue
		}

		item,err := readPemFile(fullName)
		if err != nil {
			continue
		}
		content = append(content, item)
	}

	return content
}

func readPemFile(file string) ([]byte, error) {
	bytes, err := readFile(file)
	if err != nil {
		return nil,err
	}

	b, _ := pem.Decode(bytes)
	if b == nil { // TODO: also check that the type is what we expect (cert vs key..)
		return nil,errors.New("no pem content for file %s")
	}

	return bytes,nil
}

func readFile(file string) ([]byte, error) {
	fileCont, err := ioutil.ReadFile(file)
	if err != nil {
		return nil,  err
	}

	return fileCont, nil
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}
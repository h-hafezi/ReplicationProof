package main

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"math/big"
)

////////////////////////////////////////////////// My code //////////////////////////////////////////////////

// RSAKeySize Key size in terms of bits
const RSAKeySize int = 2048

// Domain size in terms of bytes
const fixedDomainSize = (RSAKeySize)/8 + 32*8

func generateRandomByte(size int) []byte {
	buf := make([]byte, size)
	// then we can call rand.Read.
	_, err := rand.Read(buf)
	if err != nil {
		log.Fatalf("error while generating random string: %s", err)
	}
	return buf
}

func generateRSAKeyPair() (*big.Int, *big.Int, int64) {
	// Generate a 2048-bit RSA private key
	pri, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		panic("something went wrong while key generation")
	}
	// p and q are the two large prime
	p := (*pri).Primes[0]
	q := (*pri).Primes[1]
	// N is p * q
	N := big.NewInt(0)
	N.Mul(p, q)
	// d is the secret exponent
	d := (*pri).D
	// e is the public exponent
	e := int64((*pri).E)
	return N, d, e
}

// Encrypt big integer into big integer
func encryptRSA(message *big.Int, publicExponent int64, n *big.Int, b int) big.Int {
	// First compute q and r
	dv := new(big.Int).Div(message, n)
	rm := new(big.Int).Mod(message, n)
	// Get (dv + 1) * n and 2 ^ b separately
	res1 := new(big.Int).Add(dv, big.NewInt(1))
	res2 := new(big.Int).Mul(res1, n)
	res3 := new(big.Int).Lsh(big.NewInt(2), uint(b))
	res4 := res2.Cmp(res3)
	if 0 <= res4 {
		// set the result to  result = m ^ e % N
		result := big.NewInt(0)
		result.Exp(rm, big.NewInt(publicExponent), n)
		result.Add(new(big.Int).Mul(dv, n), result)
		return *result
	} else {
		return *message
	}
}

// Decrypt big integer into big integer
func decryptRSA(cipher *big.Int, privateExponent *big.Int, n *big.Int, b int) big.Int {
	// First compute q and r
	dv := new(big.Int).Div(cipher, n)
	rm := new(big.Int).Mod(cipher, n)
	// Get (dv + 1) * n and 2 ^ b separately
	res1 := new(big.Int).Add(dv, big.NewInt(1))
	res2 := new(big.Int).Mul(res1, n)
	res3 := new(big.Int).Lsh(big.NewInt(2), uint(b))
	res4 := res2.Cmp(res3)
	if 0 <= res4 {
		// set the result to  result = m ^ e % N
		result := big.NewInt(0)
		result.Exp(rm, privateExponent, n)
		result.Add(new(big.Int).Mul(dv, n), result)
		return *result
	} else {
		return *cipher
	}
}

// Takes a byte array of the fixed size (e.g. 2048 bits) and interprets that as integer
func byteToBigInteger(buf [fixedDomainSize]byte) big.Int {
	res := big.NewInt(0)
	res.SetBytes(buf[:])
	return *res
}

// Takes a big integer and converts it into a byte array of fixed
func bigIntegerToByte(number *big.Int) [fixedDomainSize]byte {
	var res [fixedDomainSize]byte
	bytePresentation := number.Bytes()
	copy(res[fixedDomainSize-len(bytePresentation):fixedDomainSize], bytePresentation)
	return res
}

func checkErr(err error) {
	if err != nil {
		fmt.Printf("Error is %+v\n", err)
		log.Fatal("ERROR:", err)
	}
}

func encryptEME(keyByte, tweak, plainText []byte) []byte {
	// GET CIPHER BLOCK USING KEY
	if len(plainText)%aes.BlockSize != 0 {
		panic("plainText is not a multiple of the block size")
	}
	block, err := aes.NewCipher(keyByte)
	checkErr(err)
	// ENCRYPT DATA
	cipherTextByte := Transform(block, tweak, plainText, DirectionEncrypt)
	return cipherTextByte
	// cipherText := hex.EncodeToString(cipherTextByte)
}

func decryptEME(keyByte, tweak, cipherTextByte []byte) []byte {
	// CHECK cipherTextByte
	// CBC mode always works in whole blocks.
	if len(cipherTextByte)%aes.BlockSize != 0 {
		panic("cipherTextByte is not a multiple of the block size")
	}
	// GET CIPHER BLOCK USING KEY
	block, err := aes.NewCipher(keyByte)
	checkErr(err)
	// DECRYPT DATA
	plainTextByte := Transform(block, tweak, cipherTextByte, DirectionDecrypt)
	return plainTextByte
}

func encodeSingleBlock(block [fixedDomainSize]byte, N big.Int, d big.Int, keyByte []byte, tweak []byte, round int) [fixedDomainSize]byte {
	address := &block
	for i := 0; i < round; i++ {
		// Encrypt byte array with AES
		result := encryptEME(keyByte, tweak, block[:])
		// Make result into a fixed array
		var arr [fixedDomainSize]byte
		copy(arr[:], result)
		// Convert the byte array into big integer
		bigIntegerResult := byteToBigInteger(arr)
		// Decrypt it with RSA
		cypher := decryptRSA(&bigIntegerResult, &d, &N, fixedDomainSize)
		// Interpret the result as a byte array
		*address = bigIntegerToByte(&cypher)
	}
	return *address
}

func decodeSingleBlock(block [fixedDomainSize]byte, N big.Int, e int64, keyByte []byte, nonce []byte, round int) [fixedDomainSize]byte {
	address := &block
	for i := 0; i < round; i++ {
		// Block into big integer
		res1 := byteToBigInteger(*address)
		// Encrypt it using RSA
		res2 := encryptRSA(&res1, e, &N, fixedDomainSize)
		// Big integer into byte array
		res3 := bigIntegerToByte(&res2)
		res4 := decryptEME(keyByte, nonce, res3[:])
		// Make result into a fixed array and assign it to address
		var arr [fixedDomainSize]byte
		copy(arr[:], res4)
		*address = arr
	}
	return *address
}

func main() {
	// RSA key generation
	N, d, e := generateRSAKeyPair()
	keyEME := generateRandomByte(32)
	// all-zero
	tweak := generateRandomByte(16)
	// make a single block
	var arr [fixedDomainSize]byte
	copy(arr[:], "abc")
	// encode and decode a single block and print it
	enc := encodeSingleBlock(arr, *N, *d, keyEME, tweak, 20)
	dec := decodeSingleBlock(enc, *N, e, keyEME, tweak, 20)
	fmt.Println(dec)
}

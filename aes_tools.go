package goaesecb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypted ecb

// NewECBEncrypted is AES Tool function
func NewECBEncrypted(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypted)(newECB(b))
}
func (x *ecbEncrypted) BlockSize() int { return x.blockSize }
func (x *ecbEncrypted) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

type ecbDecrypted ecb

// NewECBDecrypted is AES Tool function
func NewECBDecrypted(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypted)(newECB(b))
}
func (x *ecbDecrypted) BlockSize() int { return x.blockSize }
func (x *ecbDecrypted) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

// AesEncrypt is AES-ECB encrypt function
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	ecb := NewECBEncrypted(block)
	data := make([]byte, len(origData))
	ecb.CryptBlocks(data, origData)
	return data, nil
}

// AesDecrypt is AES-ECB decrypt function
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := NewECBDecrypted(block)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

// PKCS5Padding is AES Tool function
func PKCS5Padding(context []byte, blockSize int) []byte {
	padding := blockSize - len(context)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(context, padtext...)
}

// PKCS5UnPadding is AES Tool function
func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	result := int(origData[length-1])
	return origData[:(length - result)]
}

package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"github.com/baosloan/crypto/utils"
)

type encryptMode string

const (
	ModeCBC encryptMode = "CBC"
	ModeCFB encryptMode = "CFB"
	ModeECB encryptMode = "ECB"
)

// Encrypt AES对称加密
// src: 待加密的数据
// key:秘钥
// mode: 分组模式 目前支持 CBC、CFB、ECB
func Encrypt(src string, key string, mode encryptMode) ([]byte, error) {
	switch mode {
	case ModeCBC:
		return encryptCBC([]byte(src), []byte(key))
	case ModeCFB:
		return encryptCFB([]byte(src), []byte(key))
	case ModeECB:
		return encryptECB([]byte(src), []byte(key))
	default:
		return nil, errors.New("不支持的分组模式")
	}
}

func Decrypt(src []byte, key string, mode encryptMode) (string, error) {
	switch mode {
	case ModeCBC:
		return decryptCBC(src, []byte(key))
	case ModeCFB:
		return decryptCFB(src, []byte(key))
	case ModeECB:
		return decryptECB(src, []byte(key))
	default:
		return "", errors.New("不支持的分组模式")
	}
}

// encryptCBC
// plainText:明文
// key:秘钥，16、24 或 32 字节以选择 AES-128、AES-192 或 AES-256。
func encryptCBC(plainText []byte, key []byte) ([]byte, error) {
	//1.创建并返回一个新的 cipher.Block。
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//2.最后一个分组进行数据填充
	plainText = utils.PKCS5Padding(plainText, block.BlockSize())

	//3.返回一个 BlockMode，它使用给定的 Block 以密码块链接模式进行加密。
	//  iv 的长度必须与 Block 的块大小相同。
	blockMode := cipher.NewCBCEncrypter(block, key[:block.BlockSize()])

	//5.加密连续的数据块
	dst := plainText
	blockMode.CryptBlocks(dst, plainText)
	return dst, nil
}

// decryptCBC AES CBC分组解密
func decryptCBC(cipherText []byte, key []byte) (string, error) {
	//1.创建并返回一个新的 cipher.Block。
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	//2.返回一个 BlockMode，它使用给定的 Block 以密码块链接模式进行解密。
	blockMode := cipher.NewCBCDecrypter(block, key[:block.BlockSize()])
	//3.解密
	dst := make([]byte, len(cipherText))
	blockMode.CryptBlocks(dst, cipherText)
	//4.去掉尾部填充的字
	return string(utils.PKCS5UnPadding(dst)), nil
}

// encryptCFB
// plainText:明文
// key:秘钥，16、24 或 32 字节以选择 AES-128、AES-192 或 AES-256。
func encryptCFB(plainText []byte, key []byte) ([]byte, error) {
	//1.创建并返回一个新的 cipher.Block。
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//2.返回一个使用密码反馈模式加密的 Stream
	//  iv 的长度必须与 Block 的块大小相同。
	iv := key[:aes.BlockSize]
	stream := cipher.NewCFBEncrypter(block, iv)

	//4.加密连续的数据块
	dst := plainText
	stream.XORKeyStream(dst, plainText)
	return dst, nil
}

func decryptCFB(cipherText []byte, key []byte) (string, error) {
	//1.创建并返回一个新的 cipher.Block。
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	//2.获取向量,iv 的长度必须与 Block 的块大小相同
	iv := key[:aes.BlockSize]

	//3.返回一个使用给定块以密码反馈模式解密的流。
	stream := cipher.NewCFBDecrypter(block, iv)

	//4.解密连续的块
	dst := cipherText
	stream.XORKeyStream(dst, cipherText)
	return string(dst), nil
}

func encryptECB(plainText []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(utils.GenerateKey(key))
	if err != nil {
		return nil, err
	}
	length := (len(plainText) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, plainText)
	padText := byte(len(plain) - len(plainText))
	for i := len(plainText); i < len(plain); i++ {
		plain[i] = padText
	}
	cipherText := make([]byte, len(plain))
	//分组分块加密
	for bs, be := 0, block.BlockSize(); bs <= len(plainText); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(cipherText[bs:be], plain[bs:be])
	}
	return cipherText, nil
}

func decryptECB(cipherText []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(utils.GenerateKey(key))
	if err != nil {
		return "", err
	}
	plainText := make([]byte, len(cipherText))
	for bs, be := 0, block.BlockSize(); bs < len(cipherText); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Decrypt(plainText[bs:be], cipherText[bs:be])
	}

	trim := 0
	if len(plainText) > 0 {
		trim = len(plainText) - int(plainText[len(plainText)-1])
	}

	return string(plainText[:trim]), nil
}

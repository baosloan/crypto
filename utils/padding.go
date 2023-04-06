package utils

import "bytes"

// PKCS5Padding 使用pkcs5的方式填充
func PKCS5Padding(plainText []byte, blockSize int) []byte {
	//1.计算最后一个分组缺多少个字节
	padding := blockSize - len(plainText)%blockSize
	//2.创建一个大小为padding的切片
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	//3.将padText添加到原始数据的后边，将最后一个分组缺少的字节数补齐
	return append(plainText, padText...)
}

// PKCS5UnPadding 删除pkcs5填充的尾部数据
func PKCS5UnPadding(paddingText []byte) []byte {
	//1.计算数据的总长度
	length := len(paddingText)
	//2.根据填充的字节值得到填充的次数
	number := int(paddingText[length-1])
	//3.将尾部填充的number个字节去掉
	return paddingText[:length-number]
}

// ZeroPadding 零填充
func ZeroPadding(plainText []byte, blockSize int) []byte {
	//1.计算最后一个分组缺多少个字节
	padding := blockSize - len(plainText)%blockSize
	//2.创建一个大小为padding的切片
	padText := bytes.Repeat([]byte{byte(0)}, padding)
	//3.将padText添加到原始数据的后边，将最后一个分组缺少的字节数补齐
	return append(plainText, padText...)
}

// ZeroUnPadding 零反填充
func ZeroUnPadding(paddingText []byte) []byte {
	return PKCS5UnPadding(paddingText)
}

func GenerateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

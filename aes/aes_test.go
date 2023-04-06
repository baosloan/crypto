package aes

import (
	"encoding/base64"
	"log"
	"testing"
)

const (
	testDataEncryptSRC    = "123456"
	testDataEncryptKey    = "1234567812345678"
	testDataEncryptCBCDST = "2eDiseYiSX62qk/WS/ZDmg=="
	testDataEncryptCFBDST = "XJ4vYtJx"
	testDataEncryptECBDST = "mdSm0RmB+xAKrTah3DG31A=="
)

func TestEncrypt(t *testing.T) {
	//1.AES-CBC分组
	dst, err := Encrypt(testDataEncryptSRC, testDataEncryptKey, ModeCBC)
	if err != nil {
		log.Fatalf("加密出错: %v\n", err)
	}
	if base64.StdEncoding.EncodeToString(dst) != testDataEncryptCBCDST {
		log.Fatalf("AES-CBC加密算法有误!\n")
	}
	//2.AES-CFB分组
	dst, err = Encrypt(testDataEncryptSRC, testDataEncryptKey, ModeCFB)
	if err != nil {
		log.Fatalf("加密出错: %v\n", err)
	}
	if base64.StdEncoding.EncodeToString(dst) != testDataEncryptCFBDST {
		log.Fatalf("AES-CFB加密算法有误!\n")
	}
	//3.AES-ECB分组
	dst, err = Encrypt(testDataEncryptSRC, testDataEncryptKey, ModeECB)
	if err != nil {
		log.Fatalf("加密出错: %v\n", err)
	}
	if base64.StdEncoding.EncodeToString(dst) != testDataEncryptECBDST {
		log.Fatalf("AES-ECB加密算法有误!\n")
	}
}

func TestDecrypt(t *testing.T) {
	//1.AES-CBC分组
	cipherText, _ := base64.StdEncoding.DecodeString(testDataEncryptCBCDST)
	plainText, err := Decrypt(cipherText, testDataEncryptKey, ModeCBC)
	if err != nil {
		log.Fatalf("解密出错：%v\n", err)
	}
	if plainText != testDataEncryptSRC {
		log.Fatalf("AES-CBC解密算法有误!\n")
	}
	//2.AES-CFB分组
	cipherText, _ = base64.StdEncoding.DecodeString(testDataEncryptCFBDST)
	plainText, err = Decrypt(cipherText, testDataEncryptKey, ModeCFB)
	if err != nil {
		log.Fatalf("解密出错：%v\n", err)
	}
	if plainText != testDataEncryptSRC {
		log.Fatalf("AES-CFB解密算法有误!\n")
	}
	//3.AES-ECB分组
	cipherText, _ = base64.StdEncoding.DecodeString(testDataEncryptECBDST)
	plainText, err = Decrypt(cipherText, testDataEncryptKey, ModeECB)
	if err != nil {
		log.Fatalf("解密出错：%v\n", err)
	}
	if plainText != testDataEncryptSRC {
		log.Fatalf("AES-ECB解密算法有误!\n")
	}
}

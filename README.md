# Go加密技术

封装常用的Go语言加密方法，体验更友好。
>所有方法通过了单元测试，请放心使用。

目前已支持的加密技术如下：

- 散列函数
    - md5
    - sh2系列(sha224、sha256、sha384、sha512)
- 对称加密
    - CBC模式
    - CFB模式
    - ECB模式
## 安装

```shell
go get github.com/baosloan/crypto
```

## 使用

```go
package main

import (
  "github.com/baosloan/crypto/aes"
  "github.com/baosloan/crypto/hash"
)

func main() {
  //md5加密
  hash.MD5("123456")
  //sha224
  hash.SHA224("123456")
  //sha256
  hash.SHA256("123456")
  //sha384
  hash.SHA384("123456")
  //sha512
  hash.SHA512("123456")

  src, key := "123456", "1234567812345678"
  cipherText, _ := aes.Encrypt(src, key, aes.ModeCBC)
  plainText, _ := aes.Decrypt(cipherText, key, aes.ModeCBC)
}
```
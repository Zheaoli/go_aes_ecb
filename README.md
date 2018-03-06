# go_aes_ecb
Golang support for AES/ECB Encrypt/Decrypt

AES 是通用的一种标准，已经进入 RFC ，参见 [RFC 3826](https://tools.ietf.org/html/rfc3826)

目前 AES 有这样几种加密方式

1. Electronic Codebook, ECB

2. Cipher Block Chaining CBC

3. Cipher Feedback CFB

4. Output Feedback OFB

5. Counter CTR

其中 Golang 出于一些考虑，废弃了对于 ECB 的支持，但是 AES/ECB 适用范围依旧比较广泛，所以自己做了一个库来实现一套
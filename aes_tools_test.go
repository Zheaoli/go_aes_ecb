package goaesecb

import (
	"fmt"
	"testing"
)

func assertEqual(t *testing.T, a interface{}, b interface{}, message string) {
	if a == b {
		return
	}
	if len(message) == 0 {
		message = fmt.Sprintf("%v != %v", a, b)
	}
	t.Fatal(message)
}

func TestAesEncrypt(t *testing.T) {
	bizData := "abc"
	encypt, _ := AesEncrypt([]byte(bizData), []byte("0123456789abcdef"))
	data, _ := AesDecrypt(encypt, []byte("0123456789abcdef"))
	assertEqual(t, string(data), bizData, "True")
}

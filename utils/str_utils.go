package utils

import (
	"encoding/hex"
	"fmt"
	"strconv"
)

// StringToHex 将字符串转换为16进制字符串
func StringToHex(s string) string {
	hexString := ""
	for i := 0; i < len(s); i++ {
		hexString += fmt.Sprintf("%02x", s[i])
	}
	return hexString
}

// HexToString 将16进制字符串解码回原始字符串
func HexToString(h string) (string, error) {
	bytes, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func StrChangeUnit16(str *string) (num16 uint16) {
	// 将字符串转换为 uint64，再转换为 uint16

	// 将字符串转换为 uint64，再转换为 uint16
	num, err := strconv.ParseUint(*str, 10, 16)
	if err != nil {
		return num16
	}

	// 将 uint64 类型转换为 uint16 类型
	num16 = uint16(num)
	return num16
}

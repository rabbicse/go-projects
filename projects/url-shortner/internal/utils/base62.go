package utils

const base62Chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func Base62Encode(num int64) string {
	if num == 0 {
		return string(base62Chars[0])
	}

	var encoded []byte
	for num > 0 {
		remainder := num % 62
		num = num / 62
		encoded = append(encoded, base62Chars[remainder])
	}

	// Reverse the encoded string
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}

	return string(encoded)
}

func Base62EncodeBytes(data []byte) string {
	var num uint64
	for i := 0; i < 8 && i < len(data); i++ { // take first 8 bytes for int64
		num = (num << 8) | uint64(data[i])
	}

	// Encode as Base62
	if num == 0 {
		return "0"
	}
	var encoded []byte
	for num > 0 {
		encoded = append([]byte{base62Chars[num%62]}, encoded...)
		num /= 62
	}
	return string(encoded)
}

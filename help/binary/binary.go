package binary

type Endianness int

const (
	LittleEndian Endianness = iota
	BigEndian
)

func GetUint64(endianness Endianness, data []byte, offset int, numBytes int) (uint64, bool) {
	if offset < 0 || numBytes < 0 {
		return 0, false
	}

	if offset+numBytes > len(data) {
		return 0, false
	}

	var result uint64
	if endianness == LittleEndian {
		for i := numBytes - 1; i >= 0; i-- {
			result <<= 8
			result += uint64(data[offset+i])
		}
	} else if endianness == BigEndian {
		for i := 0; i < numBytes; i++ {
			result <<= 8
			result += uint64(data[offset+i])
		}
	}

	return result, true
}

func GetInt64(endianness Endianness, data []byte, offset int, numBytes int) (int64, bool) {
	v, ok := GetUint64(endianness, data, offset, numBytes)
	if !ok {
		return 0, false
	}

	if numBytes == 0 {
		return 0, true
	}

	iv := int64(v)
	intBits := uint64(numBytes) * 8
	if numBytes == 1 || numBytes == 2 || numBytes == 4 {
		sx := v&(0x80<<(intBits-8)) != 0
		if sx {
			if numBytes == 1 {
				iv = int64(int8(v))
			} else if numBytes == 2 {
				iv = int64(int16(v))
			} else if numBytes == 4 {
				iv = int64(int32(v))
			}
		}
	}

	return iv, true
}

func Uint8Le(data []byte, offset int) (uint8, bool) {
	v, ok := GetUint64(LittleEndian, data, offset, 1)
	if !ok {
		return 0, false
	}

	return uint8(v), true
}

func Uint16Le(data []byte, offset int) (uint16, bool) {
	v, ok := GetUint64(LittleEndian, data, offset, 2)
	if !ok {
		return 0, false
	}

	return uint16(v), true
}

func Uint32Le(data []byte, offset int) (uint32, bool) {
	v, ok := GetUint64(LittleEndian, data, offset, 4)
	if !ok {
		return 0, false
	}

	return uint32(v), true
}

func Uint64Le(data []byte, offset int) (uint64, bool) {
	v, ok := GetUint64(LittleEndian, data, offset, 8)
	if !ok {
		return 0, false
	}

	return v, true
}

func Int8Le(data []byte, offset int) (int8, bool) {
	v, ok := GetInt64(LittleEndian, data, offset, 1)
	if !ok {
		return 0, false
	}

	return int8(v), true
}

func Int16Le(data []byte, offset int) (int16, bool) {
	v, ok := GetInt64(LittleEndian, data, offset, 2)
	if !ok {
		return 0, false
	}

	return int16(v), true
}

func Int32Le(data []byte, offset int) (int32, bool) {
	v, ok := GetInt64(LittleEndian, data, offset, 4)
	if !ok {
		return 0, false
	}

	return int32(v), true
}

func Int64Le(data []byte, offset int) (int64, bool) {
	v, ok := GetInt64(LittleEndian, data, offset, 8)
	if !ok {
		return 0, false
	}

	return int64(v), true
}

func Uint8Be(data []byte, offset int) (uint8, bool) {
	v, ok := GetUint64(BigEndian, data, offset, 1)
	if !ok {
		return 0, false
	}

	return uint8(v), true
}

func Uint16Be(data []byte, offset int) (uint16, bool) {
	v, ok := GetUint64(BigEndian, data, offset, 2)
	if !ok {
		return 0, false
	}

	return uint16(v), true
}

func Uint32Be(data []byte, offset int) (uint32, bool) {
	v, ok := GetUint64(BigEndian, data, offset, 4)
	if !ok {
		return 0, false
	}

	return uint32(v), true
}

func Uint64Be(data []byte, offset int) (uint64, bool) {
	v, ok := GetUint64(BigEndian, data, offset, 8)
	if !ok {
		return 0, false
	}

	return v, true
}

func Int8Be(data []byte, offset int) (int8, bool) {
	v, ok := GetInt64(BigEndian, data, offset, 1)
	if !ok {
		return 0, false
	}

	return int8(v), true
}

func Int16Be(data []byte, offset int) (int16, bool) {
	v, ok := GetInt64(BigEndian, data, offset, 2)
	if !ok {
		return 0, false
	}

	return int16(v), true
}

func Int32Be(data []byte, offset int) (int32, bool) {
	v, ok := GetInt64(BigEndian, data, offset, 4)
	if !ok {
		return 0, false
	}

	return int32(v), true
}

func Int64Be(data []byte, offset int) (int64, bool) {
	v, ok := GetInt64(BigEndian, data, offset, 8)
	if !ok {
		return 0, false
	}

	return v, true
}

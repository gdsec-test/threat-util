package binary

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

var testVectors = []string{
	"1234567887654321",
	"FFEEDDCCCCDDEEFF",
	"8800880088008800",
	"0088008800880088",
	"1828384858687898",
}

func TestBinary(t *testing.T) {
	for _, s := range testVectors {
		data, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}

		if v, ok := Uint64Be(data, 0); !ok || v != binary.BigEndian.Uint64(data) {
			t.Fatal("bad result 1")
		} else if v, ok := Uint32Be(data, 0); !ok || v != binary.BigEndian.Uint32(data) {
			t.Fatal("bad result 2")
		} else if v, ok := Uint16Be(data, 0); !ok || v != binary.BigEndian.Uint16(data) {
			t.Fatal("bad result 3")
		} else if v, ok := Uint8Be(data, 0); !ok || v != data[0] {
			t.Fatal("bad result 4")
		} else if v, ok := Uint64Le(data, 0); !ok || v != binary.LittleEndian.Uint64(data) {
			t.Fatal("bad result 5")
		} else if v, ok := Uint32Le(data, 0); !ok || v != binary.LittleEndian.Uint32(data) {
			t.Fatal("bad result 6")
		} else if v, ok := Uint16Le(data, 0); !ok || v != binary.LittleEndian.Uint16(data) {
			t.Fatal("bad result 7")
		} else if v, ok := Uint8Le(data, 0); !ok || v != data[0] {
			t.Fatal("bad result 8")
		} else if v, ok := Int64Be(data, 0); !ok || v != int64(binary.BigEndian.Uint64(data)) {
			t.Fatal("bad result 9")
		} else if v, ok := Int32Be(data, 0); !ok || v != int32(binary.BigEndian.Uint32(data)) {
			t.Fatalf("bad result 10")
		} else if v, ok := Int16Be(data, 0); !ok || v != int16(binary.BigEndian.Uint16(data)) {
			t.Fatalf("bad result 11")
		} else if v, ok := Int8Be(data, 0); !ok || v != int8(data[0]) {
			t.Fatal("bad result 12")
		} else if v, ok := Int64Le(data, 0); !ok || v != int64(binary.LittleEndian.Uint64(data)) {
			t.Fatal("bad result 13")
		} else if v, ok := Int32Le(data, 0); !ok || v != int32(binary.LittleEndian.Uint32(data)) {
			t.Fatal("bad result 14")
		} else if v, ok := Int16Le(data, 0); !ok || v != int16(binary.LittleEndian.Uint16(data)) {
			t.Fatal("bad result 15")
		} else if v, ok := Int8Le(data, 0); !ok || v != int8(data[0]) {
			t.Fatal("bad result 16")
		}
	}
}

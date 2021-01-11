package triage_test

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gdcorp-infosec/threat-util/help/triage"
)

var triageTestDataHex string = `
4d5a50000200000004000f00ffff0000
b80000000000000040001a0000000000
00000000000000000000000000000000
00000000000000000000000000010000
ba10000e1fb409cd21b8014ccd219090
546869732070726f6772616d206d7573
742062652072756e20756e6465722057
696e33320d0a24370000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
504500004c010800195e422a00000000
00000000e0008f810b010219009e0000
0046000000000000f8a5000000100000
00b00000000040000010000000020000
01000000060000000400000000000000
0040010000040000a12d180002000080
00001000004000000000100000100000
00000000100000000000000000000000
00d000005009000000100100002c0000
000000000000000000b6170080170000
00000000000000000000000000000000
00000000000000000000000000000000
00f00000180000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
0000000000000000434f444500000000
309d000000100000009e000000040000
00000000000000000000000020000060
44415441000000005002000000b00000
0004000000a200000000000000000000
00000000400000c04253530000000000
900e000000c000000000000000a60000
000000000000000000000000000000c0
2e696461746100005009000000d00000
000a000000a600000000000000000000
00000000400000c02e746c7300000000
0800000000e000000000000000b00000
000000000000000000000000000000c0
2e726461746100001800000000f00000
0002000000b000000000000000000000
00000000400000502e72656c6f630000
c4080000000001000000000000000000
00000000000000000000000040000050
2e72737263000000002c000000100100
002c000000b200000000000000000000
00000000400000500000000000000000
00000000004001000000000000e80000
00000000000000000000000040000050
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
`

var triageTestDataResult = `{
  "Md5HexDigest": "DE1C4F31BEAEB0C3DFD961A5F3624881",
  "Sha1HexDigest": "E6CDC2C50DE232BA0A562D63F2D8D3422E17E25A",
  "Sha256HexDigest": "9C95B9CBB6153508A548A3C1932D33D73EB4DA016C3F1A9F205CEB38D92E7781",
  "Size": 1024,
  "ShannonEntropy": 1.973113266796047,
  "FileType": {
    "FileTypeId": 5,
    "Description": "PE Executable",
    "Extensions": [
      "exe"
    ]
  },
  "FileTypes": [
    {
      "FileTypeId": 5,
      "Description": "PE Executable",
      "Extensions": [
        "exe"
      ]
    },
    {
      "FileTypeId": 4,
      "Description": "DOS Executable",
      "Extensions": [
        "exe"
      ]
    },
    {
      "FileTypeId": 2,
      "Description": "Binary",
      "Extensions": [
        "dat",
        "bin"
      ]
    }
  ],
  "ByteDistribution": {
    "0": 813,
    "1": 10,
    "10": 2,
    "100": 3,
    "101": 3,
    "102": 0,
    "103": 1,
    "104": 1,
    "105": 3,
    "106": 0,
    "107": 0,
    "108": 2,
    "109": 2,
    "11": 1,
    "110": 3,
    "111": 2,
    "112": 1,
    "113": 0,
    "114": 8,
    "115": 4,
    "116": 4,
    "117": 3,
    "118": 0,
    "119": 0,
    "12": 0,
    "120": 0,
    "121": 0,
    "122": 0,
    "123": 0,
    "124": 0,
    "125": 0,
    "126": 0,
    "127": 0,
    "128": 2,
    "129": 1,
    "13": 1,
    "130": 0,
    "131": 0,
    "132": 0,
    "133": 0,
    "134": 0,
    "135": 0,
    "136": 0,
    "137": 0,
    "138": 0,
    "139": 0,
    "14": 2,
    "140": 0,
    "141": 0,
    "142": 0,
    "143": 1,
    "144": 3,
    "145": 0,
    "146": 0,
    "147": 0,
    "148": 0,
    "149": 0,
    "15": 1,
    "150": 0,
    "151": 0,
    "152": 0,
    "153": 0,
    "154": 0,
    "155": 0,
    "156": 0,
    "157": 1,
    "158": 2,
    "159": 0,
    "16": 10,
    "160": 0,
    "161": 1,
    "162": 1,
    "163": 0,
    "164": 0,
    "165": 1,
    "166": 2,
    "167": 0,
    "168": 0,
    "169": 0,
    "17": 0,
    "170": 0,
    "171": 0,
    "172": 0,
    "173": 0,
    "174": 0,
    "175": 0,
    "176": 4,
    "177": 0,
    "178": 1,
    "179": 0,
    "18": 0,
    "180": 1,
    "181": 0,
    "182": 1,
    "183": 0,
    "184": 2,
    "185": 0,
    "186": 1,
    "187": 0,
    "188": 0,
    "189": 0,
    "19": 0,
    "190": 0,
    "191": 0,
    "192": 5,
    "193": 0,
    "194": 0,
    "195": 0,
    "196": 1,
    "197": 0,
    "198": 0,
    "199": 0,
    "2": 6,
    "20": 0,
    "200": 0,
    "201": 0,
    "202": 0,
    "203": 0,
    "204": 0,
    "205": 2,
    "206": 0,
    "207": 0,
    "208": 2,
    "209": 0,
    "21": 0,
    "210": 0,
    "211": 0,
    "212": 0,
    "213": 0,
    "214": 0,
    "215": 0,
    "216": 0,
    "217": 0,
    "218": 0,
    "219": 0,
    "22": 0,
    "220": 0,
    "221": 0,
    "222": 0,
    "223": 0,
    "224": 2,
    "225": 0,
    "226": 0,
    "227": 0,
    "228": 0,
    "229": 0,
    "23": 2,
    "230": 0,
    "231": 0,
    "232": 1,
    "233": 0,
    "234": 0,
    "235": 0,
    "236": 0,
    "237": 0,
    "238": 0,
    "239": 0,
    "24": 3,
    "240": 2,
    "241": 0,
    "242": 0,
    "243": 0,
    "244": 0,
    "245": 0,
    "246": 0,
    "247": 0,
    "248": 1,
    "249": 0,
    "25": 2,
    "250": 0,
    "251": 0,
    "252": 0,
    "253": 0,
    "254": 0,
    "255": 2,
    "26": 1,
    "27": 0,
    "28": 0,
    "29": 0,
    "3": 0,
    "30": 0,
    "31": 1,
    "32": 7,
    "33": 2,
    "34": 0,
    "35": 0,
    "36": 1,
    "37": 0,
    "38": 0,
    "39": 0,
    "4": 5,
    "40": 0,
    "41": 0,
    "42": 1,
    "43": 0,
    "44": 3,
    "45": 1,
    "46": 5,
    "47": 0,
    "48": 1,
    "49": 0,
    "5": 0,
    "50": 1,
    "51": 1,
    "52": 0,
    "53": 0,
    "54": 0,
    "55": 1,
    "56": 0,
    "57": 0,
    "58": 0,
    "59": 0,
    "6": 1,
    "60": 0,
    "61": 0,
    "62": 0,
    "63": 0,
    "64": 11,
    "65": 2,
    "66": 2,
    "67": 1,
    "68": 2,
    "69": 2,
    "7": 0,
    "70": 1,
    "71": 0,
    "72": 0,
    "73": 0,
    "74": 0,
    "75": 0,
    "76": 2,
    "77": 1,
    "78": 0,
    "79": 1,
    "8": 3,
    "80": 9,
    "81": 0,
    "82": 0,
    "83": 2,
    "84": 2,
    "85": 0,
    "86": 0,
    "87": 1,
    "88": 0,
    "89": 0,
    "9": 3,
    "90": 1,
    "91": 0,
    "92": 0,
    "93": 0,
    "94": 1,
    "95": 0,
    "96": 1,
    "97": 5,
    "98": 1,
    "99": 2
  },
  "FuzzyHash": "6:MxlEh/jKjXFeyclltA9izeUD0r9llUMIotp0P/3BWwKXGO:OEh/G70yUQ9iKUAhPAnQwu",
  "FuzzyHash1": "MxlEh/jKjXFeyclltA9izeUD0r9llUMIotp0P/3BWwKXGO",
  "FuzzyHash2": "OEh/G70yUQ9iKUAhPAnQwu",
  "FuzzyHashBlockSize": 6,
  "Time": "0001-01-01T00:00:00Z"
}`

func TestTriage(t *testing.T) {
	data, err := hex.DecodeString(strings.Replace(triageTestDataHex, "\n", "", -1))
	if err != nil {
		t.Fatal("bad hex data")
	}

	// Triage All

	dp := &triage.DefaultProcessors{}
	err = dp.Triage(data)
	if err != nil {
		t.Fatalf("%s", err)
	}
	dp.Time.Time = time.Time{}

	jsonBytes, err := json.MarshalIndent(dp, "", "  ")
	if err != nil {
		t.Fatalf("%s", err)
	} else if string(jsonBytes) != triageTestDataResult {
		t.Fatalf("bad result")
	}
}
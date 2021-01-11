package filetype_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/gdcorp-infosec/threat-util/help/filetype"
)

type testVector struct {
	HexData string
	Id      filetype.Id
}

var malDoc = "504b030414000600080000002100470b7a240c020000630f0000130008025b436f6e74656e745f54797065735d2e786d6c20a2040228a000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bc974b6f1a311485f795fa1f46de56f32209211143164dba6c23954add1acf1d703a635bb6c3e3dff71a26288d06069ad81b10d8e79cfb6133d71edfad9b3a5a82365c8a82e4494622104c965ccc0bf26bfa2d1e91c8582a4a5a4b0105d980217793cf9fc6d38d0213a15a98822cac55b7696ad8021a6a12a940e0482575432d7ed4f35451f687ce211d64d9306552581036b6ce834cc6f750d1e7da460f6bfc7a57c98c0b127dddcd735105a14ad59c518bc3e9529449636259559c41b29cd1472d9f805992769a3d2998bf71e38dab663bd0add1509b9e0afec58c5bc40495db3966c195f982130e24ac9aaab3a875ec46ba35ceed70516dd60f5c4fcd4b881ea9b6df6983b3d295d4655a4af6dca032396ed3feba4e92ec250d655a3e083aab014729172f6407d37059eea9a56784b58a5e6763373598138cdfacd06ebfec919c97d2928131b8dd9b3ad9f9f6c783b528f05140ebdc5bc20a663fbd55f1cabcb710ca2c5fc2ef97f7fcb4d56effb8ade8fc90739e0eade89c8041088a816f8a8b101417be292e43505cfaa6b80a4171e59b62188262e89be23a04c5b56f8a51088a916f8a9b101437be29f22c48dbcbbc738469dfdefb771ea481e71fdfc12bb49aba23f6c71feaf6d6bd98162f71b07b3d653f1caf636b732c1267e2e54d19bc14eaffc056eda5cba9630456a02d3f7e86df27a2f5bbf9c0ddcd4a283bb253e767267f010000ffff0300504b0304140006000800000021001e911ab7ef0000004e0200000b0008025f72656c732f2e72656c7320a2040228a0000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000646F6350726F70732F636F72652E786D6C"

var testVectors = []testVector{
	{"4D5A", filetype.Dos},
	{"5151510D0A515151", filetype.Text},
	{"7F454C46", filetype.Elf},
	{"", filetype.Empty},
	{malDoc, filetype.OpenOfficeXml},
}

func TestFileType(t *testing.T) {
	for i, tv := range testVectors {
		data, err := hex.DecodeString(tv.HexData)
		if err != nil {
			t.Fatal(err)
		}

		filetypes := filetype.Get(data)
		if !filetypes.Matches(tv.Id) {
			t.Fatal(fmt.Sprintf("filetype mismatch: %v", i+1))
		}
	}
}

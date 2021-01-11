package filetype

import (
	"errors"
	"strconv"
	"strings"
	"unicode"

	"github.com/gdcorp-infosec/threat-util/help/binary"
)

type Id uint

const (
	None Id = iota

	Empty
	Binary
	Text

	Dos
	Pe
	Elf
	Pcap
	SqliteDatabase
	Ico
	Jpg
	Gif
	Bzip2
	Zip
	Rar
	Png
	JavaClass
	Swf
	Macho
	Ogg
	Pdf
	PostScript
	PhotoShop
	Wav
	Dmg
	Avi
	Mp3
	Iso
	Office
	Dalvik
	ChromeExtension
	Tar
	SevenZip
	Gzip
	Zlib
	Cab
	Wasm
	Rtf
	Tiff
	OpenOfficeXml
)

type signature struct {
	Nibbles         []byte
	WildcardNibbles []bool
}

type signatureEntry struct {
	FileType

	Signatures []*signature
}

type FileType struct {
	FileTypeId  Id
	Description string
	Extensions  []string
}

type FileTypes []FileType

type signatureTableEntry struct {
	Fmt        string
	FileTypeId Id
}

var signatureTable = []signatureTableEntry{
	{"7F 45 4C 46 |ELF Executable|", Elf},
	{"a1 b2 c3 d4, d4 c3 b2 a1|Packet Capture|pcap", Pcap},
	{"25 50 44 46 2d|PDF Document|pdf", Pdf},
	{"53 51 4c 69 74 65 20 66 6f 72 6d 61 74 20 33 00|SQLite Database|db", SqliteDatabase},
	{"00 00 01 00|Computer Icon|ico", Ico},
	{"47 49 46 38 37 61,47 49 46 38 39 61|GIF Image|gif", Gif},
	{"89 50 4E 47 0D 0A 1A 0A|Portable Network Graphics|png", Png},
	{"CA FE BA BE,FE ED FA CE,FE ED FA CF,CE FA ED FE,CF FA ED FE|Mach-O Binary|", Macho},
	{"CA FE BA BE|Java Class|class", JavaClass},
	{"52 49 46 46 ?? ?? ?? ?? 57 41 56 45|Waveform Audio File|wav", Wav},
	{"52 49 46 46 ?? ?? ?? ?? 41 56 49 20|Audio Video Interleave|avi", Avi},
	{"FF FB|MP3 File|mp3", Mp3},
	{"D0 CF 11 E0 A1 B1 1A E1|Office Document|doc,xls,ppt", Office},
	{"64 65 78 0A 30 33 35 00|Dalvik Executable|dex", Dalvik},
	{"75 73 74 61 72 00 30 30,75 73 74 61 72 20 20 00|Tar Archive|tar", Tar},
	{"37 7A BC AF 27 1C|7-Zip|7z", SevenZip},
	{"1F 8B|Gzip|gz", Gzip},
	{"43 57 53,46 57 53|Shockwave Flash|swf", Swf},
	{"FF D8 FF DB,FF D8 FF E0 00 10 4A 46 49 46 00 01,FF D8 FF EE,FF D8 FF E1 ?? ?? 45 78 69 66 00 00|JPEG Image|jpg,jpeg", Jpg},
	{"50 4B 03 04,50 4B 05 06,50 4B 07 08|Zip Archive|zip", Zip},
	{"52 61 72 21 1A 07 00,52 61 72 21 1A 07 01 00|RAR Archive|rar", Rar},
	{"43 44 30 30 31|ISO Image|iso", Iso},
	{"4F 67 67 53|Ogg Vorbis Data|ogg", Ogg},
	{"4D 53 43 46|Windows Cabinet Archive|cab", Cab},
	{"00 61 73 6d|WebAssembly|wasm", Wasm},
	{"42 5A 68|Bzip2 Data|bz2", Bzip2},
	{"49 49 2A 00,4D 4D 00 2A|Tagged Image File Format|tiff", Tiff},
	{"25 21 50 53|PostScript Document|ps", PostScript},
	{"43 72 32 34|Chrome Extension|crx", ChromeExtension},
	{"78 01 73 0D 62 62 60|Apple Disk Image|dmg", Dmg},
	{"7B 5C 72 74 66 31|RTF Document|rtf", Rtf},
	{"38 42 50 53|PhotoShop Document|psd", PhotoShop},
	{"78 01,78 9C,78 DA|Zlib Data|zlib", Zlib},
}

func init() {
	signatureEntries = make([]*signatureEntry, 0, len(signatureTable))

	for _, entry := range signatureTable {
		fi, err := newFileInfo(entry.Fmt, entry.FileTypeId)
		if err != nil {
			panic(err)
		}
		signatureEntries = append(signatureEntries, fi)
	}
}

func (s *signature) Matches(data []byte) bool {
	for i := 0; i < len(s.Nibbles); i += 1 {
		if i/2 >= len(data) {
			return false
		}

		if s.WildcardNibbles[i] {
			continue
		}

		b := data[i/2]
		if i%2 == 0 {
			b >>= 4
		} else {
			b &= 0x0F
		}

		if b != s.Nibbles[i] {
			return false
		}
	}

	return true
}

func newSignature(s string) (*signature, error) {
	s = removeAllWhitespace(s)

	if len(s)%2 != 0 {
		return nil, errors.New("odd-length input string")
	}

	result := &signature{}
	for i := 0; i < len(s); i++ {
		isWildcard := true
		var value byte
		if s[i] != '?' {
			v, err := strconv.ParseUint(s[i:i+1], 16, 8)
			if err != nil {
				return nil, err
			}
			value = byte(v)
			isWildcard = false
		}
		result.Nibbles = append(result.Nibbles, value)
		result.WildcardNibbles = append(result.WildcardNibbles, isWildcard)
	}

	if len(result.Nibbles) == 0 {
		return nil, errors.New("signature cannot be zero bytes")
	}

	return result, nil
}

func newFileInfo(s string, id Id) (*signatureEntry, error) {
	fi := &signatureEntry{}

	fields := strings.SplitN(s, "|", 3)
	if len(fields) < 3 {
		return nil, errors.New("bad number of fields")
	}

	hexSignatures := strings.Split(fields[0], ",")
	for _, s := range hexSignatures {
		signature, err := newSignature(s)
		if err != nil {
			return nil, err
		}

		fi.Signatures = append(fi.Signatures, signature)
	}

	if len(fi.Signatures) == 0 {
		return nil, errors.New("no signatures found")
	}

	fi.Description = strings.TrimSpace(fields[1])

	fi.Extensions = strings.Split(fields[2], ",")
	for i := 0; i < len(fi.Extensions); i++ {
		fi.Extensions[i] = strings.TrimSpace(fi.Extensions[i])
	}
	if len(fi.Extensions) == 0 {
		fi.Extensions = append(fi.Extensions, "")
	}

	fi.FileTypeId = id

	return fi, nil
}

func removeAllWhitespace(s string) string {
	sb := &strings.Builder{}
	for _, r := range s {
		if !unicode.IsSpace(r) {
			sb.WriteRune(r)
		}
	}

	return sb.String()
}

var signatureEntries []*signatureEntry

func getFinalFileType(data []byte) FileType {
	if len(data) == 0 {
		return FileType{FileTypeId: Empty, Description: "Empty", Extensions: nil}
	}

	for _, b := range data {
		if b >= 0x80 || b == 0x00 {
			return FileType{FileTypeId: Binary, Description: "Binary", Extensions: []string{"dat", "bin"}}
		}
	}

	return FileType{FileTypeId: Text, Description: "Text", Extensions: []string{"txt"}}
}

func Get1(data []byte) FileType {
	return Get(data)[0]
}

func newFile(id Id, description string, extensions ...string) FileType {
	var a []string
	for _, extension := range extensions {
		if len(extension) > 0 {
			a = append(a, extension)
		}
	}
	return FileType{FileTypeId: id, Description: description, Extensions: a}
}

// Should return least specific to most specific in the array (Example: DOS, PE, Dll, etc)
type fileTypeFunc func(data []byte) FileTypes

var fileTypeFuncs = []fileTypeFunc{
	isPeFile,
	isOfficeXml,
}

func isPeFile(p []byte) FileTypes {
	var result []FileType

	if v, ok := binary.Uint16Be(p, 0); ok && v == 0x4d5a {
		result = append(result, newFile(Dos, "DOS Executable", "exe"))

		if peOffset, ok := binary.Int32Le(p, 0x3C); ok {
			if v, ok := binary.Uint32Be(p, int(peOffset)); ok && v == 0x50450000 {
				result = append(result, newFile(Pe, "PE Executable", "exe"))
			}
		}
	}

	return result
}

func isOfficeXml(p []byte) FileTypes {
	var result []FileType

	isOfficeXml := false
	if v, ok := binary.Uint32Be(p, 0); ok && v == 0x504B0304 {
		s := string(p)
		if strings.Contains(s, "[Content_Types].xml") && strings.Contains(s, "docProps/core.xml") {
			isOfficeXml = true
		}
	}

	if isOfficeXml {
		result = append(result, newFile(OpenOfficeXml, "Open Office XML", "docx", "pptx", "xlsx"))
	}

	return result
}

func (ft *FileType) Matches(id Id) bool {
	return ft.FileTypeId == id
}

func (fts FileTypes) Matches(id Id) bool {
	for _, ft := range fts {
		if ft.Matches(id) {
			return true
		}
	}

	return false
}

func Get(data []byte) FileTypes {
	var result []FileType

	// Match using functions first
	for _, f := range fileTypeFuncs {
		ft := f(data)
		// Iterate in reverse to add the most specific type first in the result array
		for i := len(ft) - 1; i >= 0; i-- {
			result = append(result, ft[i])
		}
	}

	// Match with signature
	for _, fi := range signatureEntries {
	InnerLoop:
		for _, s := range fi.Signatures {
			if s.Matches(data) {
				result = append(result, fi.FileType)
				break InnerLoop
			}
		}
	}

	// Match against file initial type
	result = append(result, getFinalFileType(data))

	return result
}

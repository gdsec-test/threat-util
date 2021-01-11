package processors

import (
	"github.secureserver.net/threat/hashtype"
)

type Hashes struct {
	ProcessorBase

	Md5HexDigest    string
	Sha1HexDigest   string
	Sha256HexDigest string
}

func (h *Hashes) Triage(p []byte) {
	t := hashtype.NewHashTripletFromData(p)

	h.Md5HexDigest = t.Md5.HexDigest
	h.Sha1HexDigest = t.Sha1.HexDigest
	h.Sha256HexDigest = t.Sha256.HexDigest

	h.AcceptedData = true
}

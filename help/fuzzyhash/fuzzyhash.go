// Ported from: https://github.com/tridge/junkcode/blob/master/spamsum/spamsum.c

package fuzzyhash

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gdcorp-infosec/threat-util/help/distance"
)

const (
	RollingWindowSize = uint32(7)
	SumSize           = uint32(64)
	MinBlockSize      = uint32(3)
)

var Prime uint32 = 0x01000193
var Init uint32 = 0x28021967

type FuzzyHash struct {
	Hash1     string
	Hash2     string
	BlockSize uint32
}

var ErrInvalidHash = errors.New("invalid fuzzy hash")

func FromString(fuzzyHash string) (*FuzzyHash, error) {
	a := strings.SplitN(fuzzyHash, ":", 4)
	if len(a) != 3 {
		return nil, ErrInvalidHash
	}

	blockSize64, err := strconv.ParseUint(a[0], 10, 32)
	if err != nil {
		return nil, ErrInvalidHash
	}

	blockSize := uint32(blockSize64)
	if blockSize < MinBlockSize {
		return nil, ErrInvalidHash
	}

	for _, s := range []string{a[1], a[2]} {
		for _, c := range s {
			if (c < 'A' && c > 'Z') && (c < 'a' && c > 'z') && (c < '0' && c > '9') && c != '+' && c != '/' {
				return nil, ErrInvalidHash
			}
		}
	}

	return &FuzzyHash{BlockSize: blockSize, Hash1: a[1], Hash2: a[2]}, nil
}

func (h *FuzzyHash) String() string {
	return fmt.Sprintf("%v:%s:%s", h.BlockSize, h.Hash1, h.Hash2)
}

type RollingHash struct {
	Window [RollingWindowSize]byte
	H      [3]uint32
	N      uint32
}

func sumHash(h uint32, b byte) uint32 {
	return h*Prime ^ uint32(b)
}

func (r *RollingHash) Update(value byte) uint32 {
	b := uint32(value)

	r.H[1] -= r.H[0]
	r.H[1] += RollingWindowSize * b

	r.H[0] += b
	r.H[0] -= uint32(r.Window[r.N%RollingWindowSize])

	r.Window[r.N%RollingWindowSize] = byte(b)
	r.N += 1

	r.H[2] <<= 5
	r.H[2] ^= b

	return r.H[0] + r.H[1] + r.H[2]
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func HashToString(p []byte) string {
	return Hash(p).String()
}

var distanceContext = distance.New(1, 1, 5, 3, true)

func SimilarityFromStrings(fuzzyHash1, fuzzyHash2 string) float64 {
	f1, err := FromString(fuzzyHash1)
	if err != nil {
		return 0.0
	}

	f2, err := FromString(fuzzyHash2)
	if err != nil {
		return 0.0
	}

	return Similarity(f1, f2)
}

func Similarity(x, y *FuzzyHash) float64 {
	var p, q string
	if x.BlockSize == y.BlockSize {
		p = x.Hash1
		q = y.Hash1
	} else if x.BlockSize/2 == y.BlockSize {
		p = x.Hash2
		q = y.Hash1
	} else if y.BlockSize/2 == x.BlockSize {
		p = x.Hash1
		q = y.Hash2
	} else {
		return 0.0
	}

	if len(p)+len(q) == 0 {
		return 1.0
	}

	d := distanceContext.Get(p, q)
	difference := d / float64(len(p)+len(q))
	similarity := 1.0 - difference

	if similarity > 1.0 {
		return 1.0
	} else if similarity < 0.0 {
		return 0.0
	}

	return similarity
}

func (h *FuzzyHash) Similarity(other *FuzzyHash) float64 {
	return Similarity(h, other)
}

func Hash(p []byte) *FuzzyHash {
	blockSize := MinBlockSize
	for blockSize*SumSize < uint32(len(p)) {
		blockSize *= 2
	}

	for {
		var rh RollingHash

		trigger := uint32(0)

		var hash1 [SumSize]byte
		var hash2 [SumSize / 2]byte
		i := uint32(0)
		j := uint32(0)

		h1pr := Init
		h2pr := Init
		for _, b := range p {
			trigger = rh.Update(b)
			h1pr = sumHash(h1pr, b)
			h2pr = sumHash(h2pr, b)

			if trigger%blockSize == blockSize-1 {
				hash1[i] = base64Alphabet[h1pr%64]
				if i < SumSize-1 {
					h1pr = Init
					i += 1
				}
			}

			if trigger%(blockSize*2) == (blockSize*2)-1 {
				hash2[j] = base64Alphabet[h2pr%64]
				if j < SumSize/2-1 {
					h2pr = Init
					j += 1
				}
			}
		}

		if blockSize > MinBlockSize && i < SumSize/2 {
			blockSize /= 2
			continue
		}

		if trigger != 0 {
			hash1[i] = base64Alphabet[h1pr%64]
			hash2[j] = base64Alphabet[h2pr%64]
			i += 1
			j += 1
		}

		return &FuzzyHash{
			Hash1:     string(hash1[:i]),
			Hash2:     string(hash2[:j]),
			BlockSize: blockSize,
		}
	}
}

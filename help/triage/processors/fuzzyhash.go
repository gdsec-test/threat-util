package processors

import "github.com/gdcorp-infosec/threat-util/help/fuzzyhash"

type FuzzyHash struct {
	ProcessorBase

	FuzzyHash string

	FuzzyHash1         string
	FuzzyHash2         string
	FuzzyHashBlockSize uint32
}

func (fh *FuzzyHash) Triage(p []byte) {
	h := fuzzyhash.Hash(p)

	fh.FuzzyHash1 = h.Hash1
	fh.FuzzyHash2 = h.Hash2
	fh.FuzzyHashBlockSize = h.BlockSize

	fh.FuzzyHash = h.String()

	fh.AcceptedData = true
}

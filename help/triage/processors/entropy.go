package processors

import (
	"github.com/gdcorp-infosec/threat-util/help/shannonentropy"
)

type ShannonEntropy struct {
	ProcessorBase

	ShannonEntropy float64
}

func (e *ShannonEntropy) Triage(p []byte) {
	var d [256]uint64
	for _, b := range p {
		d[b] += 1
	}

	e.ShannonEntropy = shannonentropy.Compute(d)
	e.AcceptedData = true
}

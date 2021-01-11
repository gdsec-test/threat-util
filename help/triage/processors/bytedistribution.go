package processors

type ByteDistribution struct {
	ProcessorBase

	ByteDistribution map[byte]int
}

func (bd *ByteDistribution) Triage(p []byte) {
	var Counts [256]int
	for _, b := range p {
		Counts[b] += 1
	}

	bd.ByteDistribution = map[byte]int{}
	for i := 0; i < len(Counts); i++ {
		bd.ByteDistribution[byte(i)] = Counts[i]
	}

	bd.AcceptedData = true
}

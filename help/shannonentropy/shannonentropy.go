package shannonentropy

import (
	"bytes"
	"io"
	"math"
	"strings"
)

func Get(r io.Reader) (float64, error) {
	var d [256]uint64
	var err error

	p := make([]byte, 1024)
	for {
		var n int
		n, err = r.Read(p)
		for i := 0; i < n; i++ {
			d[p[i]] += 1
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return 0.0, err
		}
	}

	return Compute(d), nil
}

func GetFromSlice(p []byte) float64 {
	result, _ := Get(bytes.NewReader(p))
	return result
}

func GetFromString(p string) float64 {
	result, _ := Get(strings.NewReader(p))
	return result
}

func Compute(byteDistribution [256]uint64) float64 {
	// Compute sum of byte distribution
	var sum uint64
	for _, count := range byteDistribution {
		sum += count
	}

	// Convert sum to float and guard against zero values
	sumf := float64(sum)
	if sumf == 0.0 {
		return 0.0
	}

	// Compute resulting Shannon Entropy value
	var shannonEntropy float64
	for _, count := range byteDistribution {
		pct := float64(count) / sumf
		if pct != 0.0 {
			shannonEntropy += -pct * math.Log2(pct)
		}
	}

	// Saturate result
	if shannonEntropy > 8.0 {
		shannonEntropy = 8.0
	} else if shannonEntropy < 0.0 {
		shannonEntropy = 0.0
	}

	return shannonEntropy
}

package shannonentropy_test

import (
	"testing"

	"github.com/gdcorp-infosec/threat-util/help/shannonentropy"
)

func TestShannonEntropy(t *testing.T) {
	data := "aalsjflasjfkljasklfjalksjflkj"
	if shannonentropy.GetFromString(data) != 2.5604227026072035 {
		t.Fatal("bad entropy")
	}
}

package distance

import (
	"testing"
)

func TestDistance(t *testing.T) {
	d := New(1, 1, 1, 3, true)

	if d.Get("ABC", "ABD") != 2 {
		t.Fatal("bad distance")
	}
}

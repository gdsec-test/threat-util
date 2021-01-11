package sscounter_test

import (
	"reflect"
	"testing"

	"github.com/gdcorp-infosec/threat-util/help/sscounter"
)

func TestSubstringCounter(t *testing.T) {
	sc := sscounter.New(sscounter.CaseInsensitive, sscounter.DelimiterFuncWhitespace)
	sc.Update("Asdf Asdf asdf zxcv zxcv abc")
	if sc.Top1(1) != "Asdf" {
		t.Fatalf("bad top count")
	} else if !reflect.DeepEqual(sc.TopN(2, false, 0), []string{"Asdf", "zxcv"}) {
		t.Fatalf("bad top count")
	} else if !reflect.DeepEqual(sc.TopNWithBlacklist(2, false, 0, []string{"Asdf"}), []string{"zxcv", "abc"}) {
		t.Fatalf("bad top count")
	} else if !reflect.DeepEqual(sc.TopN(2, false, 3), []string{"Asdf"}) {
		t.Fatalf("bad top count")
	}
}

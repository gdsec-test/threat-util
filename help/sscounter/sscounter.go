package sscounter

import (
	"sort"
	"strings"
	"unicode"
)

type SubstringCounter struct {
	Counts          map[string]map[string]int
	CaseSensitivity CaseSensitivity
	SplitFunc       IsDelimiterFunc
}

type IsDelimiterFunc func(r rune) bool

var DelimiterFuncNonAlphaNumeric IsDelimiterFunc = func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }
var DelimiterFuncNonPrintable IsDelimiterFunc = func(r rune) bool { return !unicode.IsPrint(r) }
var DelimiterFuncWhitespace IsDelimiterFunc = func(r rune) bool { return unicode.IsSpace(r) }

type CaseSensitivity bool

var CaseSensitive CaseSensitivity = true
var CaseInsensitive CaseSensitivity = false

func New(caseSensitivity CaseSensitivity, isDelimiter IsDelimiterFunc) *SubstringCounter {
	mfs := &SubstringCounter{}

	mfs.Counts = map[string]map[string]int{}
	mfs.CaseSensitivity = caseSensitivity
	mfs.SplitFunc = isDelimiter

	return mfs
}

func (sc *SubstringCounter) Top1(minCount int) string {
	results := sc.TopN(1, true, minCount)
	if len(results) == 0 {
		return ""
	}

	return results[0]
}

// Returns most frequent substring, and total count of all values
func sum(m map[string]int) (string, int) {
	max := ""
	lastMax := 0

	s := 0

	for k, v := range m {
		s += v
		if v > lastMax {
			lastMax = v
			max = k
		}
	}

	return max, s
}

func in(l []string, str string, caseSensitivity CaseSensitivity) bool {
	if caseSensitivity == CaseInsensitive {
		str = strings.ToLower(str)
	}

	for _, s := range l {
		if caseSensitivity == CaseInsensitive {
			if strings.ToLower(s) == str {
				return true
			}
		} else {
			if s == str {
				return true
			}
		}
	}

	return false
}

func (sc *SubstringCounter) TopNWithBlacklist(n int, hardLimit bool, minCount int, blacklist []string) []string {
	if n <= 0 {
		return nil
	}

	maxValues := make([]int, n)
	for k, m := range sc.Counts {
		if in(blacklist, k, sc.CaseSensitivity) {
			continue
		}

		_, count := sum(m)

		minIdx := -1
		for i := range maxValues {
			if count > maxValues[i] {
				if minIdx == -1 {
					minIdx = i
				} else {
					if maxValues[i] < maxValues[minIdx] {
						minIdx = i
					}
				}
			}
		}
		if minIdx != -1 {
			maxValues[minIdx] = count
		}
	}

	sort.Sort(sort.Reverse(sort.IntSlice(maxValues)))

	var result []string
	for _, maxValue := range maxValues {
		for k, m := range sc.Counts {
			if in(blacklist, k, sc.CaseSensitivity) {
				continue
			}

			str, count := sum(m)
			if maxValue == count && maxValue >= minCount {
				result = append(result, str)
				if hardLimit && len(result) == n {
					return result
				}
			}
		}
	}

	return result
}

func (sc *SubstringCounter) TopN(n int, hardLimit bool, minCount int) []string {
	return sc.TopNWithBlacklist(n, hardLimit, minCount, nil)
}

func (sc *SubstringCounter) add(s string) {
	k := s
	if sc.CaseSensitivity == CaseInsensitive {
		k = strings.ToLower(s)
	}

	if _, ok := sc.Counts[k]; !ok {
		sc.Counts[k] = map[string]int{}
	}

	sc.Counts[k][s] += 1
}

func (sc *SubstringCounter) Update(s string) {

	if sc.SplitFunc != nil {
		sb := &strings.Builder{}
		for _, r := range s {
			if sc.SplitFunc(r) {
				if sb.Len() > 0 {
					sc.add(sb.String())
					sb.Reset()
				}
			} else {
				sb.WriteRune(r)
			}
		}
		if sb.Len() > 0 {
			sc.add(sb.String())
		}
	} else {
		sc.add(s)
	}
}

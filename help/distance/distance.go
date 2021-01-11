package distance

import (
	"encoding/csv"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Distance object which contains cost values, case sensitivity, and the replacement character table
type Distance struct {
	insertCost         float64
	deleteCost         float64
	transposeCost      float64
	replaceDefaultCost float64
	caseSensitive      bool
	replacementTable   map[string]float64
}

type matrixEntry struct {
	cost       float64
	transposed bool
}

func min3(a, b, c float64) float64 {
	return math.Min(a, math.Min(b, c))
}

// Get calculates the distance starting from one string to shift it to another.
func (d *Distance) Get(to, from string) float64 {
	// Lowercase the strings according to ASCII rules if case insensitivity is desired
	if !d.caseSensitive {
		to = strings.ToLower(to)
		from = strings.ToLower(from)
	}

	// Convert the string to runes
	s1 := []rune(to)
	s2 := []rune(from)

	// Special case zero-length strings since tables below require valid indices
	if len(s1) == 0 {
		return (float64)(len(s2)) * d.insertCost
	}
	if len(s2) == 0 {
		return (float64)(len(s1)) * d.deleteCost
	}

	// Create the 2d matrix of costs and transpose statuses
	m := make([][]matrixEntry, len(s1)+1)
	for i := range m {
		m[i] = make([]matrixEntry, len(s2)+1)
	}

	// First column contains increasing cost of deletion
	for i := 0; i < len(s1)+1; i++ {
		m[i][0].cost = ((float64)(i)) * d.insertCost
	}

	// Second row contains increasing cost of insertion
	for i := 0; i < len(s2)+1; i++ {
		m[0][i].cost = ((float64)(i)) * d.deleteCost
	}

	// Traverse the matrix, calculating the lowest cost operation for each element given its adjacent values
	for j := 1; j < len(s2)+1; j++ {
		for i := 1; i < len(s1)+1; i++ {
			// Determine the lowest cost of insertion, deletion, and replacement
			cost := min3(
				m[i-1][j].cost+d.insertCost,
				m[i][j-1].cost+d.deleteCost,
				m[i-1][j-1].cost+d.GetReplacementCost(s1[i-1], s2[j-1]))

			// See if the two preceding characters are reversible if they haven't already been transposed
			justTransposed := false
			if i >= 2 && j >= 2 {
				if s1[i-2] == s2[j-1] && s1[i-1] == s2[j-2] && !m[i-1][j-1].transposed {
					// Skip back 1 action and use the transpose cost instead if its lower
					transposeCost := m[i-2][j-2].cost + d.transposeCost
					if transposeCost < cost {
						cost = transposeCost
						justTransposed = true
					}
				}
			}

			// Store this elements minimum cost and tranposed status to the table
			m[i][j] = matrixEntry{cost, justTransposed}
		}
	}

	return m[len(s1)][len(s2)].cost
}

// GetReplacementCost gets the cost of replacing character c with the specified replacement
func (d *Distance) GetReplacementCost(c rune, replacement rune) float64 {
	if c == replacement {
		return 0.0
	}

	key := fmt.Sprintf("%c%c", c, replacement)

	result := d.replaceDefaultCost
	if val, ok := d.replacementTable[key]; ok {
		result = val
	}

	return result
}

// SetReplacementCost sets the cost of replacing character c with its replacement
func (d *Distance) SetReplacementCost(c rune, replacement rune, cost float64) error {
	key := fmt.Sprintf("%c%c", c, replacement)
	if c == replacement {
		return errors.New("Character and replacement must be different")
	}

	if _, ok := d.replacementTable[key]; ok {
		return errors.New("Value pair already exists")
	}

	d.replacementTable[key] = cost

	return nil
}

// LoadReplacementTableFromFile loads Replacement data from a CSV file in the form
// a,b,cost where a is the source character, b is the replacement, and cost is the
// floating point cost to make the replacement
func (d *Distance) LoadReplacementTableFromFile(fileName string) error {

	csvfile, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer csvfile.Close()

	reader := csv.NewReader(csvfile)
	reader.FieldsPerRecord = 3
	data, err := reader.ReadAll()
	if err != nil {
		return err
	}

	d.replacementTable = make(map[string]float64)

	lineNumber := 0
	for _, row := range data {
		lineNumber++
		value, err := strconv.ParseFloat(row[2], 64)
		if err != nil {
			return err
		}
		c := []rune(row[0])
		r := []rune(row[1])
		if len(c) != 1 || len(r) != 1 {
			return fmt.Errorf("Value does not contain single runes in line %d: %s/%s", lineNumber, row[0], row[1])
		}
		err = d.SetReplacementCost(c[0], r[0], value)
		if err != nil {
			return err
		}
	}

	return nil
}

// LoadReplacementTableFromMap loads replacement data from the map in the form map['ab'] = cost where a is the source
// character and b is the replacement.
func (d *Distance) LoadReplacementTableFromMap(replacementTable map[string]float64) error {
	d.replacementTable = make(map[string]float64)
	for k, v := range replacementTable {
		d.replacementTable[k] = v
	}

	return nil
}

// New creates new Distance object that can be used to get the distance between two strings.
//
// insertCost is the cost to insert a character. Usually 1.
// deleteCost is the cost to delete a character. Usually 1.
// transposeCost is the cost to swap two characters. Usually 1.
// replaceDefaultCost is the cost to replace one character with another. Usually 3.
// caseSensitive if True makes the comparisons case-sensitive.
//
func New(insertCost float64, deleteCost float64, transposeCost float64, replaceDefaultCost float64, caseSensitive bool) *Distance {
	d := &Distance{}

	d.replacementTable = make(map[string]float64)

	d.insertCost = insertCost
	d.deleteCost = deleteCost
	d.transposeCost = transposeCost
	d.replaceDefaultCost = replaceDefaultCost
	d.caseSensitive = caseSensitive

	return d
}

// Check if an error is present and if so, display the error and exit
func checkerr(err error) {
	if err != nil {
		fmt.Printf("Fatal error: %s", err.Error())
		os.Exit(-1)
	}
}

func main() {
	// Verify correct number of arguments
	if len(os.Args) < 8 {
		fmt.Printf("Usage: %s <insert> <delete> <transpose> <replace default> <replace table filename> <to> <from>\n", filepath.Base(os.Args[0]))
		os.Exit(-1)
	}

	/// Parse arguments into variables
	insertCost, err := strconv.ParseFloat(os.Args[1], 64)
	checkerr(err)
	deleteCost, err := strconv.ParseFloat(os.Args[2], 64)
	checkerr(err)
	transposeCost, err := strconv.ParseFloat(os.Args[3], 64)
	checkerr(err)
	replaceDefaultCost, err := strconv.ParseFloat(os.Args[4], 64)
	checkerr(err)

	// Create the string distance context
	d := New(insertCost, deleteCost, transposeCost, replaceDefaultCost, true)

	// Load the dareplacement table from file
	replacementDataCsvFile := os.Args[5]
	err = d.LoadReplacementTableFromFile(replacementDataCsvFile)
	checkerr(err)

	// Get the strings to operate on
	toString := os.Args[6]
	fromString := os.Args[7]

	// Use the distance context to calculate the string distance and then display the result
	fmt.Printf("Distance(To:'%s' From:'%s'): %f\n", toString, fromString, d.Get(toString, fromString))

	// Exit with success
	os.Exit(0)
}

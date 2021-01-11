package triage

import (
	"reflect"

	. "github.com/gdcorp-infosec/threat-util/help/triage/processors"
)

type Processor interface {
	Triage([]byte)
	HasAcceptedData() bool
	Err() error
}

type DefaultProcessors struct {
	Hashes
	Size
	ShannonEntropy
	FileType
	ByteDistribution
	FuzzyHash
	Time
}

func (dp *DefaultProcessors) Triage(data []byte) error {
	*dp = DefaultProcessors{}
	return TriageWithProcessors(data, []Processor{&dp.Hashes, &dp.Size, &dp.ShannonEntropy, &dp.FileType, &dp.ByteDistribution, &dp.FuzzyHash, &dp.Time})
}

func TriageWithProcessors(data []byte, processors []Processor) error {
	for _, p := range processors {
		p.Triage(data)
	}

	for _, p := range processors {
		if p.HasAcceptedData() {
			err := p.Err()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func Triage(data []byte) (*DefaultProcessors, error) {
	dp := &DefaultProcessors{}
	err := dp.Triage(data)
	if err != nil {
		return nil, err
	}

	return dp, nil
}

func TriageFields(data []byte, v interface{}) error {
	value := reflect.ValueOf(v)

	var processors []Processor
	for i := 0; i < value.NumField(); i++ {
		if processor, ok := value.Field(i).Interface().(Processor); ok {
			processors = append(processors, processor)
		}
	}

	return TriageWithProcessors(data, processors)
}

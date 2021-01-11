package processors

type ProcessorBase struct {
	Error        error `json:",omitempty"`
	AcceptedData bool  `json:"-"`
}

func (pb *ProcessorBase) Err() error {
	return pb.Error
}

func (pb *ProcessorBase) HasAcceptedData() bool {
	return pb.AcceptedData
}

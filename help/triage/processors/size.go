package processors

type Size struct {
	ProcessorBase

	Size int
}

func (s *Size) Triage(p []byte) {
	s.Size = len(p)

	s.AcceptedData = true
}

package processors

import "time"

type Time struct {
	ProcessorBase

	Time time.Time
}

func (t *Time) Triage(p []byte) {
	t.Time = time.Now()

	t.AcceptedData = true
}

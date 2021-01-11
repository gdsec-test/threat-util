package processors

import (
	"github.com/gdcorp-infosec/threat-util/help/filetype"
)

type FileType struct {
	ProcessorBase

	FileType  filetype.FileType
	FileTypes filetype.FileTypes
}

func (ft *FileType) Triage(p []byte) {
	ft.FileTypes = filetype.Get(p)
	ft.FileType = ft.FileTypes[0]

	ft.AcceptedData = true
}

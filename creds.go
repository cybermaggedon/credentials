/****************************************************************************

  Credential generic code.

****************************************************************************/

package credentials

import (
	"os"
)

// Format description
type Format struct {

	// Format ID.  This is passed to Get()
	Id string

	// Human readable description
	Description string
}

type CredentialPayload struct {

	// Payload type, machine readable:
	Id string

	// Payload type, one of: cert key p12 password
	Type string

	Description string

	// One of: display store
	Disposition string

	// Suggested filename
	Filename string

	// Payload
	Payload []byte
}

// Generic credential interface
type Credential interface {

	// Describes credential to stdout, human-readable
	Describe(*os.File, bool)

	// Get Format descriptors
	GetFormats() []Format

	// Gets credential
	Get(*Client, string) ([]CredentialPayload, error)

	// Returns unique cred ID
	GetId() string

	// Get credential type
	GetType() string

	// Get credential description
	GetDescription() string

	// Get credential validity start
	GetStart() string

	// Get credential validity end
	GetEnd() string
}

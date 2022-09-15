/****************************************************************************

  VPN service credentials-specific code.

****************************************************************************/

package credentials

import (
	"errors"
	"fmt"
	"os"
)

// VPN serivce credential defintion
type VpnServiceCredential struct {

	// Credential unique ID
	Id string `json:"id,omitempty"`

	// Credential user
	User string `json:"user,omitempty"`

	// Credential type, should be 'vpn-service'.
	Type string `json:"type,omitempty"`

	// Credential name.
	Name string `json:"name,omitempty"`

	// Credential human-readable description.
	Description string `json:"description,omitempty"`

	// Credential encrypted encryption key.
	Key string `json:"key,omitempty"`

	// Credential validity start time, from X.509 certificate.
	Start string `json:"start,omitempty"`

	// Credential validity end time, from X.509 certificate.
	End string `json:"end,omitempty"`

	// Name of storage object containing credential raw bundle, a P12 file.
	Bundle string `json:"bundle,omitempty"`

	// Name of storage object containing credential password, used to
	// decrypt the P12 file.
	Password string `json:"password,omitempty"`

	// Name of address allocator endpoint
	Allocator string `json:"allocator,omitempty"`

	// Name of storage object containing DH server params
	Dh string `json:"dh,omitempty"`

	// Name of storage object containing probe credential
	ProbeKey string `json:"probekey,omitempty"`

	// Name of storage object containing TA key
	Ta string `json:"ta,omitempty"`

	// Credential hostname.
	Host string `json:"host,omitempty"`
}

// Components of a web credential
type VpnServiceCredentialPayloads struct {

	// P12 bundle
	P12 []byte

	// Password used to encrypt P12 bundle
	Password []byte

	// DH params payload
	Dh []byte

	// TA params payload
	Ta []byte

	// Probe key
	ProbeKey []byte
}

// Describe credential to stdout.
func (c VpnServiceCredential) Describe(file *os.File, verbose bool) {
	if verbose {
		fmt.Fprintf(file, "VPN service credential %s\n", c.Id)
		fmt.Fprintf(file, "  Name: %s\n", c.Name)
		fmt.Fprintf(file, "  Description: %s\n", c.Description)
		fmt.Fprintf(file, "  Host: %s\n", c.Host)
	} else {
		fmt.Println(c.Id)
	}
}

// Get raw credential P12 and password.  Returns raw P12 byte string,
// password byte string and error.
func (c VpnServiceCredential) GetRaw(client *Client) (*VpnServiceCredentialPayloads, error) {

	// Fetch private/public bundle in P12 format.
	payload, err := client.GetContent(c.User, c.Bundle, c.Key)
	if err != nil {
		return nil, err
	}

	// Get bundle password
	password, err := client.GetContent(c.User, c.Password, c.Key)
	if err != nil {
		return nil, err
	}

	// Get DH param bundle
	dh, err := client.GetContent(c.User, c.Dh, c.Key)
	if err != nil {
		return nil, err
	}

	// Get TA key bundle
	ta, err := client.GetContent(c.User, c.Ta, c.Key)
	if err != nil {
		return nil, err
	}

	// Get probe cred key
	probekey, err := client.GetContent(c.User, c.ProbeKey, c.Key)
	if err != nil {
		return nil, err
	}

	return &VpnServiceCredentialPayloads{
		payload, password, dh, ta, probekey,
	}, nil

}

func (c VpnServiceCredential) GetFormats() []Format {
	return []Format{
		{"raw", "All credentials in same form as in store"},
	}
}

// Download credential in specified format.
func (c VpnServiceCredential) Get(client *Client, format string) ([]CredentialPayload, error) {

	if format == "" {
		format = "p12"
	}

	if format == "p12" {

		// Get P12 and password.
		creds, err := c.GetRaw(client)
		if err != nil {
			return nil, err
		}

		return []CredentialPayload{
			{
				"p12",
				"p12",
				"VPN server key P12 bundle",
				"store",
				c.Bundle,
				creds.P12,
			},
			{
				"dh.server",
				"dh",
				"DH params",
				"store",
				"dh.server",
				creds.Dh,
			},
			{
				"ta.key",
				"ta",
				"TA key",
				"store",
				"ta.key",
				creds.Ta,
			},
			{
				"password",
				"password",
				"Password for P12 bundles",
				"show",
				"",
				creds.Password,
			},
			{
				"allocator",
				"hostname",
				"Allocator hostname",
				"show",
				"",
				[]byte(c.Allocator),
			},
			{
				"probekey",
				"password",
				"Probe key",
				"show",
				"",
				[]byte(creds.ProbeKey),
			},
		}, nil

	} else {
		return nil, errors.New("Output format should be one of: pem, p12")
	}

}

// Get credential ID
func (c VpnServiceCredential) GetId() string {
	return c.Id
}

// Get credential type
func (c VpnServiceCredential) GetType() string {
	return c.Type
}

// Get credential description
func (c VpnServiceCredential) GetDescription() string {
	return c.Description
}

// Get credential validity start
func (c VpnServiceCredential) GetStart() string {
	return c.Start
}

// Get credential validity end
func (c VpnServiceCredential) GetEnd() string {
	return c.End
}

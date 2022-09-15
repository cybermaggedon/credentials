/****************************************************************************

  Web credentials-specific code.

****************************************************************************/

package credentials

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"os"
	"strings"
)

// Web credential defintion
type WebCredential struct {

	// Credential unique ID
	Id string `json:"id,omitempty"`

	// Credential user
	User string `json:"user,omitempty"`

	// Credential type, should be 'web'.
	Type string `json:"type,omitempty"`

	// Credential name, CN from X.509 certificate.
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
}

// Components of a web credential
type WebCredentialPayloads struct {

	// P12 bundle
	P12 []byte

	// Password used to encrypt P12 bundle
	Password []byte
}

// Describe credential to stdout.
func (c WebCredential) Describe(file *os.File, verbose bool) {
	if verbose {
		fmt.Fprintf(file, "Web credential %s\n", c.Id)
		fmt.Fprintf(file, "  Name: %s\n", c.Name)
		fmt.Fprintf(file, "  Description: %s\n", c.Description)
	} else {
		fmt.Println(c.Id)
	}
}

// Get raw credential P12 and password.  Returns raw P12 byte string,
// password byte string and error.
func (c WebCredential) GetP12(client *Client) (*WebCredentialPayloads, error) {

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

	return &WebCredentialPayloads{payload, password}, nil

}

// Output credential to a PEM file.
func (c WebCredential) GetPem(client *Client) ([]CredentialPayload, error) {

	// Get P12 and password.
	creds, err := c.GetP12(client)
	if err != nil {
		return nil, err
	}

	// Filename constructed by replacing .p12 suffix with .pem
	bundle := strings.TrimSuffix(c.Bundle, ".p12") + ".pem"

	f := bytes.Buffer{}

	blocks, err := pkcs12.ToPEM(creds.P12, string(creds.Password))
	if err != nil {
		return nil, err
	}

	for _, block := range blocks {

		// Some things (OpenSSL) want to see EC PRIVATE KEY
		if block.Type == "PRIVATE KEY" {
			block.Type = "EC PRIVATE KEY"
		}

		// Some things (OpenSSL) don't like headers
		block.Headers = map[string]string{}
		f.Write(pem.EncodeToMemory(block))

	}

	pay := make([]byte, len(f.Bytes()))
	copy(pay, f.Bytes())

	return []CredentialPayload{
		{
			"pem",
			"pem",
			"PEM bundle",
			"store",
			bundle,
			pay,
		},
	}, nil

}

func (c WebCredential) GetFormats() []Format {
	return []Format{
		{"p12", "Credentials as P12 bundle"},
		{"pem", "Concatenated PEM format credentials"},
		{"mobileconfig", "Credentials as mobileconfig for iOS device"},
	}
}

// Download credential in specified format.
func (c WebCredential) Get(client *Client, format string) ([]CredentialPayload, error) {

	if format == "" {
		format = "p12"
	}

	if format == "pem" {
		return c.GetPem(client)
	}

	if format == "mobileconfig" {
		return c.GetMC(client)
	}

	if format == "p12" {

		// Get P12 and password.
		creds, err := c.GetP12(client)
		if err != nil {
			return nil, err
		}

		return []CredentialPayload{
			{
				"p12",
				"p12",
				"P12 bundle",
				"store",
				c.Bundle,
				creds.P12,
			},
			{
				"password",
				"password",
				"Password for P12 bundle",
				"show",
				"",
				creds.Password,
			},
		}, nil

	} else {
		return nil, errors.New("Output format should be one of: pem, p12, mobileconfig")
	}

}

// Get credential ID
func (c WebCredential) GetId() string {
	return c.Id
}

// Get credential type
func (c WebCredential) GetType() string {
	return c.Type
}

// Get credential description
func (c WebCredential) GetDescription() string {
	return c.Description
}

// Get credential validity start
func (c WebCredential) GetStart() string {
	return c.Start
}

// Get credential validity end
func (c WebCredential) GetEnd() string {
	return c.End
}

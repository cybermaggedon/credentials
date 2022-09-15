/****************************************************************************

  Outputting mobileconfig configuration for IOS/macos devices.

  This constructs an .mobileconfig file by packaging the P12 file.

****************************************************************************/

package credentials

import (
	"fmt"
	"github.com/DHowett/go-plist"
	"strings"
)

// Construct P12 payload for a web cert, for encoding to mobileconfig
func (c WebCredential) p12Payload(p12 []byte, pwd, name, uuid string) payload {
	return payload{
		Password:            pwd,
		CertificateFileName: name,
		Content:             p12,
		Description:         "Adds a PKCS#12-formatted certificate",
		DisplayName:         name,
		Identifier:          "com.apple.security.pkcs12." + uuid,
		Type:                "com.apple.security.pkcs12",
		UUID:                uuid,
		Version:             1,
	}
}

// Outputs mobileconfig web certificates.
func (c WebCredential) GetMC(client *Client) ([]CredentialPayload, error) {

	// Get P12 and password.
	creds, err := c.GetP12(client)
	if err != nil {
		return nil, err
	}

	// Make up some UUIDs for the configuration structure.  Not really
	// sure what these all are, saw them in the .mobileconfig file.
	p12PayUuid := makeUUID()
	cfgUuid := makeUUID()

	// Construct the structure which will be converted into a mobileconfig
	// file

	// Payload list.
	pays := []payload{
		// Payload for the P12 bundle.
		c.p12Payload(creds.P12, string(creds.Password), "web-cert.p12",
			p12PayUuid),
	}

	// Over-arching configuration
	p := configuration{
		Payloads:          pays,
		DisplayName:       "Example web credential",
		Identifier:        "example-web-cert",
		RemovalDisallowed: false,
		Type:              "Configuration",
		UUID:              cfgUuid,
		Version:           1,
	}

	if client.mcIdentifier != "" {
		p.Identifier = client.mcIdentifier
	}
	if client.mcName != "" {
		p.DisplayName = client.mcName
	}
	if client.mcDescription != "" {
		p.Description = client.mcDescription
	}

	// Marshal the data to a byte array.
	pdata, err := plist.MarshalIndent(p, plist.XMLFormat, "\t")
	if err != nil {
		return nil, err
	}

	// Sign, if needed.
	if client.signCredentials {
		pdata, err = client.Sign(pdata)
		fmt.Println("Signed.")
		if err != nil {
			return nil, err
		}
	}

	// Filename constructed by replacing .p12 suffix with .mobileconfig
	file := strings.TrimSuffix(c.Bundle, ".p12") + ".mobileconfig"

	return []CredentialPayload{
		{
			"mobileconfig",
			"mobileconfig",
			"Mobileconfig file for iOS",
			"store",
			file,
			pdata,
		},
	}, nil

}

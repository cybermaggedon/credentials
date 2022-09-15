/****************************************************************************

  VPN credential-specific code.

****************************************************************************/

package credentials

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
)

// VPN credential defintion
type VpnCredential struct {

	// Credential unique ID
	Id string `json:"id,omitempty"`

	// Credential user
	User string `json:"user,omitempty"`

	// Credential type, should be 'vpn'.
	Type string `json:"type,omitempty"`

	// VPN device ID.
	Device string `json:"device,omitempty"`

	// Credential human-readable description.
	Description string `json:"description,omitempty"`

	// Credential encrypted encryption key.
	Key string `json:"key,omitempty"`

	// Credential validity start time, from X.509 certificate.
	Start string `json:"start,omitempty"`

	// Credential validity end time, from X.509 certificate.
	End string `json:"end,omitempty"`

	// Device type e.g. linux
	DeviceType string `json:"device_type,omitempty"`

	// Name of storage object containing UK VPN, an OpenVPN file
	Uk string `json:"uk,omitempty"`

	// Name of storage object containing US VPN, an OpenVPN file
	Us string `json:"us,omitempty"`
}

// Components of a VPN credential
type VpnCredentialPayloads struct {

	// Private key
	Key *pem.Block

	// Public cert
	Cert *pem.Block

	// CA cert
	Ca *pem.Block

	// Transport key
	Ta *pem.Block
}

// Describe credential to stdout.
func (c VpnCredential) Describe(file *os.File, verbose bool) {
	if verbose {
		fmt.Fprintf(file, "VPN credential %s\n", c.Id)
		fmt.Fprintf(file, "  Device: %s\n", c.Device)
		fmt.Fprintf(file, "  Description: %s\n", c.Description)
	} else {
		fmt.Println(c.Id)
	}
}

// Get PEM payloads from OpenVPN configuration.
func (c VpnCredential) GetPem(client *Client) (*VpnCredentialPayloads, error) {

	payload, err := c.GetOpenVPN(client, "uk")
	if err != nil {
		return nil, err
	}

	// Fragile code follows, which makes assumptions about the structure
	// of things.

	// Get the user certificate from the OpenVPN configuration by
	// searching for <cert>...</cert>
	re := regexp.MustCompile("<cert>([^<]+)</cert>")
	sub := re.FindStringSubmatch(string(payload))[1]
	cert, _ := pem.Decode([]byte(sub))

	// Get the CA certificate from the OpenVPN configuration by searching
	// for <ca>...</ca>
	re = regexp.MustCompile("<ca>([^<]+)</ca>")
	sub = re.FindStringSubmatch(string(payload))[1]
	ca, _ := pem.Decode([]byte(sub))

	// Get the private key from the OpenVPN configuration by searching
	// for <key>...</key>
	re = regexp.MustCompile("<key>([^<]+)</key>")
	sub = re.FindStringSubmatch(string(payload))[1]
	key, _ := pem.Decode([]byte(sub))

	// Get the TA key from the OpenVPN configuration by searching
	// for <tls-auth>...</tls-auth>
	re = regexp.MustCompile("<tls-auth>([^<]+)</tls-auth>")
	sub = re.FindStringSubmatch(string(payload))[1]
	ta, _ := pem.Decode([]byte(sub))

	return &VpnCredentialPayloads{key, cert, ca, ta}, nil

}

// Get payload as a P12 form.
func (c VpnCredential) GetP12(client *Client, password string) ([]byte, error) {

	// Fetch crypto keys
	creds, err := c.GetPem(client)

	// Parse user PEM data for a certificate
	cert, err := x509.ParseCertificate(creds.Cert.Bytes)
	if err != nil {
		return nil, err
	}

	// Parse CA certificate PEM data for a certificate
	ca, err := x509.ParseCertificate(creds.Ca.Bytes)
	if err != nil {
		return nil, err
	}

	// Parse PEM data for a ECDSA key.  Assumes EC key.
	key, err := x509.ParseECPrivateKey(creds.Key.Bytes)
	if err != nil {
		return nil, err
	}

	// Construct a PKCS12 payload from the key, certificate and CA cert.
	p12, err := pkcs12.Encode(rand.Reader, key, cert,
		[]*x509.Certificate{ca}, password)
	if err != nil {
		return nil, err
	}

	return p12, nil

}

// Get an OpenVPN for the specified country (should be uk or us).
func (c VpnCredential) GetOpenVPN(client *Client, cn string) ([]byte, error) {

	if cn == "uk" {

		// Download UK bundle
		return client.GetContent(c.User, c.Uk, c.Key)

	}

	if cn == "us" {

		// Download UK bundle
		return client.GetContent(c.User, c.Us, c.Key)

	}

	return nil, errors.New("Don't understand country " + cn)

}

// Download credential in specified format.
func (c VpnCredential) Get(client *Client, format string) ([]CredentialPayload, error) {

	if format == "" {
		format = "ovpn"
	}

	if format == "p12" {

		password := "x"

		pay, err := c.GetP12(client, password)
		if err != nil {
			return nil, err
		}

		base := strings.Trim(c.Uk, "-uk.ovpn")

		return []CredentialPayload{
			{
				"p12",
				"p12",
				"P12 bundle",
				"store",
				base + ".p12",
				pay,
			},
			{
				"password",
				"password",
				"Password for P12 bundle",
				"show",
				"",
				[]byte(password),
			},
		}, nil

	}

	if format == "mobileconfig-ipsec" {

		return c.GetMCIpsec(client)

	}
	// OpenVPN mobileconfig form - not tested.
	if format == "mobileconfig-ovpn" {
		return c.GetMCOpenVpn(client)
	}

	if format == "pem" {

		creds, err := c.GetPem(client)
		if err != nil {
			return nil, err
		}

		pay := []byte{}

		pay = append(pay, pem.EncodeToMemory(creds.Key)...)
		pay = append(pay, pem.EncodeToMemory(creds.Cert)...)
		pay = append(pay, pem.EncodeToMemory(creds.Ca)...)

		base := strings.Trim(c.Uk, "-uk.ovpn")

		return []CredentialPayload{
			{
				"pem",
				"pem",
				"PEM bundle",
				"store",
				base + ".pem",
				pay,
			},
		}, nil

	}

	if format == "sswan" {
		return c.GetSSwan(client)
	}

	if format == "sswan-basic" {
		return c.GetSSwanBasic(client)
	}

	if format == "ovpn" {

		// Output OpenVPN forms
		uk, err := c.GetOpenVPN(client, "uk")
		if err != nil {
			return nil, err
		}

		us, err := c.GetOpenVPN(client, "us")
		if err != nil {
			return nil, err
		}

		return []CredentialPayload{
			{
				"uk",
				"openvpn",
				"UK OpenVPN configuration",
				"store",
				c.Uk,
				uk,
			},
			{
				"us",
				"openvpn",
				"US OpenVPN configuration",
				"store",
				c.Us,
				us,
			},
		}, nil
	}

	return nil,
		errors.New("Don't understand output format '" + format + "'")

}

func (c VpnCredential) GetFormats() []Format {
	return []Format{
		{"ovpn", "OpenVPN configuration files"},
		{"p12", "Credentials as P12 bundle"},
		{"pem", "Concatenated PEM format credentials"},
		{"mobileconfig-ipsec", "IPsec mobileconfig for iOS device"},
		{"mobileconfig-ovpn", "OpenVPN mobileconfig for iOS device"},
		{"sswan", "StrongSwan configuration file for Android"},
		{"sswan-basic", "StrongSwan configuration files"},
	}
}

// Get credential ID
func (c VpnCredential) GetId() string {
	return c.Id
}

// Get credential type
func (c VpnCredential) GetType() string {
	return c.Type
}

// Get credential description
func (c VpnCredential) GetDescription() string {
	return c.Description
}

// Get credential validity start
func (c VpnCredential) GetStart() string {
	return c.Start
}

// Get credential validity end
func (c VpnCredential) GetEnd() string {
	return c.End
}

/****************************************************************************

  StrongSwan configuration for Android and Linux.

****************************************************************************/

package credentials

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
)

// Structures for JSON-encoding to sswan configuration file.

// StrongSwan remote configuration
type ssRemote struct {
	Addr string `json:"addr,omitempty"`
}

// Strongswan local configuration
type ssLocal struct {
	Id  string `json:"id,omitempty"`
	P12 string `json:"p12,omitempty"`
}

// Strongswan configuration.
type sswan struct {
	Uuid   string   `json:"uuid,omitempty"`
	Name   string   `json:"name,omitempty"`
	Type   string   `json:"type,omitempty"`
	Remote ssRemote `json:"remote,omitempty"`
	Local  ssLocal  `json:"local,omitempty"`
}

// Creation of sswan configuration file, used by Android.
func (c VpnCredential) GetSSwan(client *Client) ([]CredentialPayload, error) {

	// Get OpenVPN configuration
	payload, err := c.GetOpenVPN(client, "uk")
	if err != nil {
		return nil, err
	}

	// Get a P12 payload with no password.
	password := ""
	p12, err := c.GetP12(client, password)
	if err != nil {
		return nil, err
	}

	// Get the device certificate.
	// Fetch crypto keys
	creds, err := c.GetPem(client)

	// Parse user PEM data for a certificate
	cert, err := x509.ParseCertificate(creds.Cert.Bytes)
	if err != nil {
		return nil, err
	}

	// Need at least one DNS name for the device.
	if len(cert.DNSNames) < 1 {
		return nil,
			errors.New("Certificate doesn't contain device DNS name")
	}

	// Assume first DNS name is device name
	device := cert.DNSNames[0]

	// Encode P12 to base64.
	p12Enc := base64.StdEncoding.EncodeToString([]byte(p12))

	// Get the remote hostname from the configuration file.
	re := regexp.MustCompile("\nremote ([^ \n]+)[\n ]")
	host := re.FindStringSubmatch(string(payload))[1]

	// Translate the VPN service names to IPsec form.  Assumes
	// OpenVPN services are uk-vpn.BLAH and IPsec services are
	// us-vpn.BLAH and uk-vpn.BLAH
	host = strings.TrimPrefix(host, "uk-vpn.")
	ukHost := "uk-ipsec." + host
	usHost := "us-ipsec." + host

	// Create the sswan structure.
	vpn := sswan{
		Uuid: makeUUID(),
		Name: "Example UK VPN",
		Type: "ikev2-cert",
		Remote: ssRemote{
			Addr: ukHost,
		},
		Local: ssLocal{
			Id:  device,
			P12: p12Enc,
		},
	}

	// Output as JSON.
	ukData, err := json.Marshal(&vpn)
	if err != nil {
		return nil, err
	}

	// Modify structure for US VPN.
	vpn.Uuid = makeUUID()
	vpn.Name = "Example US VPN"
	vpn.Remote.Addr = usHost

	// JSON encode.
	usData, err := json.Marshal(&vpn)
	if err != nil {
		return nil, err
	}

	// Get filename base.
	base := strings.TrimSuffix(c.Uk, "-uk.ovpn")

	return []CredentialPayload{
		{
			"uk",
			"sswan",
			"UK StrongSwan configuration",
			"store",
			base + "-uk.sswan",
			ukData,
		},
		{
			"us",
			"sswan",
			"US StrongSwan configuration",
			"store",
			base + "-us.sswan",
			usData,
		},
	}, nil

}

// Output the various 'native' StrongSwan configuration file
func (c VpnCredential) GetSSwanBasic(client *Client) ([]CredentialPayload, error) {

	// Fetch crypto keys
	creds, err := c.GetPem(client)

	// Parse user PEM data for a certificate
	certObj, err := x509.ParseCertificate(creds.Cert.Bytes)
	if err != nil {
		return nil, err
	}

	// Need at least one DNS name for the device.
	if len(certObj.DNSNames) < 1 {
		return nil,
			errors.New("Certificate doesn't contain device DNS name")
	}

	// Get device name from cert.
	deviceId := certObj.DNSNames[0]
	device := strings.TrimSuffix(deviceId, ".device.local")

	// Write ipsec.secrets file
	f := bytes.Buffer{}
	f.WriteString(" : ECDSA \"/etc/strongswan/ipsec.d/private/" + device + ".pem\"\n")
	ipsecSecrets := make([]byte, len(f.Bytes()))
	copy(ipsecSecrets, f.Bytes())

	// Write ipsec.conf file
	f = bytes.Buffer{}
	f.WriteString("config setup\n")
	f.WriteString("\n")
	f.WriteString("conn base\n")
	f.WriteString("        dpdaction=restart\n")
	f.WriteString("        ikelifetime=60m\n")
	f.WriteString("        keylife=20m\n")
	f.WriteString("        rekeymargin=3m\n")
	f.WriteString("        keyingtries=1\n")
	f.WriteString("\n")
	f.WriteString("conn common\n")
	f.WriteString("        also=base\n")
	f.WriteString("        left=%any\n")
	f.WriteString("        leftid=" + deviceId + "\n")
	f.WriteString("        leftsourceip=%config\n")
	f.WriteString("        leftcert=/etc/strongswan/ipsec.d/certs/" + device + ".crt\n")
	f.WriteString("        right=uk-ipsec.example.com\n")
	f.WriteString("        rightsubnet=0.0.0.0/0,::/0\n")
	f.WriteString("\n")
	f.WriteString("conn ikev2\n")
	f.WriteString("        also=common\n")
	f.WriteString("	keyexchange=ikev2\n")
	f.WriteString("        auto=start\n")
	ipsecConf := make([]byte, len(f.Bytes()))
	copy(ipsecConf, f.Bytes())

	// Private key
	key := pem.EncodeToMemory(creds.Key)

	// Write certificate.
	cert := pem.EncodeToMemory(creds.Cert)

	// Write CA certificate.
	ca := pem.EncodeToMemory(creds.Ca)

	return []CredentialPayload{
		{
			"ipsec.secrets",
			"config",
			"ipsec.secrets configuration",
			"store",
			"ipsec.secrets",
			ipsecSecrets,
		},
		{
			"ipsec.conf",
			"config",
			"ipsec.conf configuration",
			"store",
			"ipsec.conf",
			ipsecConf,
		},
		{
			"key",
			"key",
			"Private key",
			"store",
			device + ".pem",
			key,
		},
		{
			"cert",
			"cert",
			"Certificate",
			"store",
			device + ".crt",
			cert,
		},
		{
			"ca",
			"ca",
			"CA certificate",
			"store",
			"ca.crt",
			ca,
		},
	}, nil

}

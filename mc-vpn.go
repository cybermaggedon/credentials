/****************************************************************************

  Outputting mobileconfig configuration for IOS/macos devices.

  This constructs an .mobileconfig file by parsing stuff out of the
  OpenVPN configuration, so is a little dependent on what happens to construct
  up-stream OpenVPN configuration files.  Also, makes assumptions about the
  key type, and the structure of VPN service names.

  If anything changes up-stream, this could be a little fragile.

****************************************************************************/

package credentials

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/DHowett/go-plist"
	"regexp"
	"strings"
)

// ProxyConfiguration for mobileconfig encoding
func (c VpnCredential) proxyConfig() *proxies {
	return &proxies{
		HTTPEnable:  0,
		HTTPSEnable: 0,
	}
}

// ChildSecurityAssocationParameters for mobileconfig encoding
func (c VpnCredential) saParams() *childSecurityAssociationParameters {
	return &childSecurityAssociationParameters{
		DiffieHellmanGroup:  14,
		EncryptionAlgorithm: "AES-256",
		IntegrityAlgorithm:  "SHA2-256",
		LifeTimeInMinutes:   1440,
	}
}

// IPv4 settings for mobileconfig encoding
func (c VpnCredential) ipv4() *ipv4 {
	return &ipv4{OverridePrimary: 1}
}

// IKEv2 for mobileconfig encoding
func (c VpnCredential) ikev2(device, p12PayUuid, host string) *ikev2 {
	return &ikev2{
		AuthenticationMethod:                      "Certificate",
		CertificateType:                           "ECDSA256",
		ChildSecurityAssociationParameters:        c.saParams(),
		DeadPeerDetectionRate:                     "Medium",
		DisableMOBIKE:                             0,
		DisableRedirect:                           0,
		EnableCertificateRevocationCheck:          false,
		EnablePFS:                                 0,
		IKESecurityAssociationParameters:          c.saParams(),
		LocalIdentifier:                           device,
		PayloadCertificateUUID:                    p12PayUuid,
		RemoteAddress:                             host,
		RemoteIdentifier:                          host,
		UseConfigurationAttributeInternalIPSubnet: 0,
		DisconnectOnIdle:                          0,
		OnDemandEnabled:                           0,
		OnDemandRules: []onDemandRule{
			onDemandRule{Action: "Connect"},
		},
	}
}

// OpenVPN vendor configuration for mobileconfig encoding
func (c VpnCredential) openVPNVendorConfig(ca, cert, key, host, tls string) *map[string]string {
	return &map[string]string{
		"ca":              ca,
		"cert":            cert,
		"key":             key,
		"client":          "NOARGS",
		"dev":             "tun",
		"proto":           "tcp",
		"sndbuf":          "0",
		"rcvbuf":          "0",
		"remote":          host + " 443",
		"resolv-retry":    "infinite",
		"nobind":          "NOARGS",
		"persist-key":     "NOARGS",
		"persist-tun":     "NOARGS",
		"remote-cert-tls": "server",
		"cipher":          "AES-256-CBC",
		"auth":            "SHA256",
		"comp-lzo":        "NOARGS",
		"setenv":          "opt block-outside-dns",
		"key-direction":   "1",
		"tls-auth":        tls,
		"vpn-on-demand":   "0",
	}
}

// Payload for the CA certificate.
func (c VpnCredential) caPayload(ca []byte, uuid string) payload {
	return payload{
		CertificateFileName: "ca.crt",
		Content:             ca,
		Description:         "Adds a CA root certificate",
		DisplayName:         "Example VPN CA",
		Identifier:          "com.apple.security.root." + uuid,
		Type:                "com.apple.security.root",
		UUID:                uuid,
		Version:             1,
	}
}

// P12 payload for mobileconfig encoding
func (c VpnCredential) p12Payload(p12 []byte, pwd, name, uuid string) payload {
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

// OpenVPN VPN settings.
func (c VpnCredential) openVPN(p12PayUuid string) *vpn {
	return &vpn{
		AuthenticationMethod: "Certificate",
		RemoteAddress:        "DEFAULT",
	}
}

// Returns a PEM in the right format for OpenVPN mobileconfig file.
func blockPem(in *pem.Block) string {
	return strings.Replace(string(pem.EncodeToMemory(in)), "\n", "\\n", -1)
}

// Outputs mobileconfig IPsec form.
func (c VpnCredential) GetMCIpsec(client *Client) ([]CredentialPayload, error) {

	cred, err := c.GetOpenVPN(client, "uk")
	if err != nil {
		return nil, err
	}

	// The P12 payload is emitted with a password.  iOS requires a
	// password to be in place, but it's not really protecting anything
	// as the password is emitted in cleartext in the .mobileconfig
	// file.  Thus .mobileconfig files should be handled as secrets.
	password := "x"

	// Construct P12 payload.
	p12, err := c.GetP12(client, password)
	if err != nil {
		return nil, err
	}

	// Fetch crypto keys
	creds, err := c.GetPem(client)

	// Parse user PEM data for a certificate
	cert, err := x509.ParseCertificate(creds.Cert.Bytes)
	if err != nil {
		return nil, err
	}

	// Get the remote hostname from the configuration file.
	re := regexp.MustCompile("\nremote ([^ \n]+)[\n ]")
	host := re.FindStringSubmatch(string(cred))[1]

	// Translate the VPN service names to IPsec form.  Assumes
	// OpenVPN services are uk-vpn.BLAH and IPsec services are
	// us-vpn.BLAH and uk-vpn.BLAH
	host = strings.TrimPrefix(host, "uk-vpn.")
	ukHost := "uk-ipsec." + host
	usHost := "us-ipsec." + host

	// Make up some UUIDs for the configuration structure.  Not really
	// sure what these all are, saw them in the .mobileconfig file.
	caPayUuid := makeUUID()
	p12PayUuid := makeUUID()
	ukVpnPayUuid := makeUUID()
	usVpnPayUuid := makeUUID()
	cfgUuid := makeUUID()

	// Need at least one DNS name for the device.
	if len(cert.DNSNames) < 1 {
		return nil,
			errors.New("Certificate doesn't contain device DNS name")
	}

	// Assume first DNS name is device name
	device := cert.DNSNames[0]

	// Construct the structure which will be converted into a mobileconfig
	// file

	// Payload list.
	pays := []payload{

		// Payload for the CA certificate.
		c.caPayload(creds.Ca.Bytes, caPayUuid),

		// Payload for the P12 bundle.
		c.p12Payload(p12, password, device+".p12", p12PayUuid),

		// Payload for the UK IKEv2 configuration
		payload{
			IKEv2:           c.ikev2(device, p12PayUuid, ukHost),
			IPv4:            c.ipv4(),
			Description:     "Configures VPN settings",
			DisplayName:     "VPN",
			Identifier:      "com.apple.vpn.managed." + ukVpnPayUuid,
			Type:            "com.apple.vpn.managed",
			UUID:            ukVpnPayUuid,
			Version:         1,
			Proxies:         c.proxyConfig(),
			UserDefinedName: "Example (UK) IPsec",
			VPNType:         "IKEv2",
		},

		// Payload for the US IKEv2 configuration
		payload{
			IKEv2:           c.ikev2(device, p12PayUuid, usHost),
			IPv4:            c.ipv4(),
			Description:     "Configures VPN settings",
			DisplayName:     "VPN",
			Identifier:      "com.apple.vpn.managed." + usVpnPayUuid,
			Type:            "com.apple.vpn.managed",
			UUID:            usVpnPayUuid,
			Version:         1,
			Proxies:         c.proxyConfig(),
			UserDefinedName: "Example (US) IPsec",
			VPNType:         "IKEv2",
		},
	}

	// Over-arching configuration
	p := configuration{
		Payloads:          pays,
		DisplayName:       "Example VPN",
		Identifier:        device,
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

	file := strings.TrimSuffix(c.Uk, "-uk.ovpn") + ".mobileconfig"

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

// OpenVPN mobileconfig form - not tested.
func (c VpnCredential) GetMCOpenVpn(client *Client) ([]CredentialPayload, error) {

	cred, err := c.GetOpenVPN(client, "uk")
	if err != nil {
		return nil, err
	}

	// Fetch crypto keys
	creds, err := c.GetPem(client)

	// Parse user PEM data for a certificate
	cert, err := x509.ParseCertificate(creds.Cert.Bytes)
	if err != nil {
		return nil, err
	}

	// Get the remote hostname from the configuration file.
	re := regexp.MustCompile("\nremote ([^ \n]+)[\n ]")
	host := re.FindStringSubmatch(string(cred))[1]

	// Translate the VPN service names to VPN form.  Assumes
	// OpenVPN services are uk-vpn.BLAH.
	host = strings.TrimPrefix(host, "uk-vpn.")
	ukHost := "uk-vpn." + host
	usHost := "us-vpn." + host

	// Make up some UUIDs for the configuration structure.  Not really
	// sure what these all are, saw them in the .mobileconfig file.
	ukVpnPayUuid := makeUUID()
	usVpnPayUuid := makeUUID()
	cfgUuid := makeUUID()

	// Need at least one DNS name for the device.
	if len(cert.DNSNames) < 1 {
		return nil, errors.New("Certificate doesn't contain device DNS name")
	}

	// Assume first DNS name is device name
	device := cert.DNSNames[0]

	// Construct the structure which will be converted into a mobileconfig
	// file

	// Payload list.
	pays := []payload{

		// Payload for the UK OpenVPN configuration
		payload{
			VPN:             c.openVPN(""),
			Description:     "Configures VPN settings",
			DisplayName:     "VPN",
			Identifier:      "com.apple.vpn.managed." + ukVpnPayUuid,
			Type:            "com.apple.vpn.managed",
			UUID:            ukVpnPayUuid,
			Version:         1,
			UserDefinedName: "Example (UK) OpenVPN",
			VPNType:         "VPN",
			VPNSubType:      "net.openvpn.connect.app",
			VendorConfig: c.openVPNVendorConfig(
				blockPem(creds.Ca),
				blockPem(creds.Cert),
				blockPem(creds.Key),
				ukHost,
				blockPem(creds.Ta),
			),
		},

		// Payload for the US OpenVPN configuration
		payload{
			VPN:             c.openVPN(""),
			Description:     "Configures VPN settings",
			DisplayName:     "VPN",
			Identifier:      "com.apple.vpn.managed." + usVpnPayUuid,
			Type:            "com.apple.vpn.managed",
			UUID:            usVpnPayUuid,
			Version:         1,
			Proxies:         c.proxyConfig(),
			UserDefinedName: "Example (US) OpenVPN",
			VPNType:         "VPN",
			VPNSubType:      "net.openvpn.connect.app",
			VendorConfig: c.openVPNVendorConfig(
				blockPem(creds.Ca),
				blockPem(creds.Cert),
				blockPem(creds.Key),
				usHost,
				blockPem(creds.Ta),
			),
		},
	}

	// Over-arching configuration
	p := configuration{
		Payloads:          pays,
		DisplayName:       "Example VPN",
		Identifier:        device,
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

	file := strings.TrimSuffix(c.Uk, "-uk.ovpn") + ".mobileconfig"

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

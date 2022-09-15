/****************************************************************************

  Outputting mobileconfig configuration for IOS/macos devices.

  Mobileconfig definitions.

  If anything changes up-stream, this could be a little fragile.

****************************************************************************/

package credentials

import (
	"github.com/google/uuid"
	"strings"
)

// This is iOS plist support.  Not a complete plist definition, just enough
// to produce the VPN configuration files.  This is reverse-engineered from
// a working .mobileconfig file, so I'm not completely sure I know what all
// this stuff does.

// Top level mobileconfig configuration object
type configuration struct {
	Payloads          []payload `plist:"PayloadContent"`
	DisplayName       string    `plist:"PayloadDisplayName"`
	Identifier        string    `plist:"PayloadIdentifier"`
	Description       string    `plist:"PayloadDescription,omitempty"`
	RemovalDisallowed bool      `plist:"PayloadRemovalDisallowed"`
	Type              string    `plist:"PayloadType"`
	UUID              string    `plist:"PayloadUUID"`
	Version           int       `plist:"PayloadVersion"`
}

// Mobileconfig Payload
type payload struct {
	Password            string             `plist:"Password,omitempty"`
	CertificateFileName string             `plist:"PayloadCertificateFileName,omitempty"`
	Content             []byte             `plist:"PayloadContent,omitempty"`
	Description         string             `plist:"PayloadDescription,omitempty"`
	DisplayName         string             `plist:"PayloadDisplayName,omitempty"`
	Identifier          string             `plist:"PayloadIdentifier,omitempty"`
	Type                string             `plist:"PayloadType,omitempty"`
	UUID                string             `plist:"PayloadUUID,omitempty"`
	Version             int                `plist:"PayloadVersion,omitempty"`
	IKEv2               *ikev2             `plist:"IKEv2,omitempty"`
	VPN                 *vpn               `plist:"VPN,omitempty"`
	IPv4                *ipv4              `plist:"IPv4,omitempty"`
	Proxies             *proxies           `plist:"Proxies,omitempty"`
	UserDefinedName     string             `plist:"UserDefinedName,omitempty"`
	VPNType             string             `plist:"VPNType,omitempty"`
	VPNSubType          string             `plist:"VPNSubType,omitempty"`
	VendorConfig        *map[string]string `plist:"VendorConfig,omitempty"`
}

// Mobileconfig OnDemandRule
type onDemandRule struct {
	Action string `plist:"Action,omitempty"`
}

// Mobileconfig IKEv2 configuration
type ikev2 struct {
	Name                               string                              `plist:"Name,omitempty"`
	AuthenticationMethod               string                              `plist:"AuthenticationMethod,omitempty"`
	CertificateType                    string                              `plist:"CertificateType,omitempty"`
	ChildSecurityAssociationParameters *childSecurityAssociationParameters `plist:"ChildSecurityAssociationParameters,omitempty"`
	IKESecurityAssociationParameters   *childSecurityAssociationParameters `plist:"IKESecurityAssociationParameters"`

	DeadPeerDetectionRate                     string         `plist:"DeadPeerDetectionRate"`
	DisableMOBIKE                             int            `plist:"DisableMOBIKE"`
	DisableRedirect                           int            `plist:"DisableRedirect"`
	EnableCertificateRevocationCheck          bool           `plist:"EnableCertificateRevocationCheck"`
	EnablePFS                                 int            `plist:"EnablePFS"`
	LocalIdentifier                           string         `plist:"LocalIdentifier,omitempty"`
	PayloadCertificateUUID                    string         `plist:"PayloadCertificateUUID,omitempty"`
	RemoteAddress                             string         `plist:"RemoteAddress,omitempty"`
	RemoteIdentifier                          string         `plist:"RemoteIdentifier,omitempty"`
	UseConfigurationAttributeInternalIPSubnet int            `plist:"UseConfigurationAttributeInternalIPSubnet"`
	DisconnectOnIdle                          int            `plist:"DisconnectOnIdle"`
	OnDemandEnabled                           int            `plist:"OnDemandEnabled"`
	OnDemandRules                             []onDemandRule `plist:"OnDemandRules,omitempty"`
}

// Mobileconfig VPN configuration
type vpn struct {
	Name                   string `plist:"Name,omitempty"`
	AuthenticationMethod   string `plist:"AuthenticationMethod,omitempty"`
	PayloadCertificateUUID string `plist:"PayloadCertificateUUID,omitempty"`
	RemoteAddress          string `plist:"RemoteAddress,omitempty"`
	RemoteIdentifier       string `plist:"RemoteIdentifier,omitempty"`
	OnDemandEnabled        int    `plist:"OnDemandEnabled"`
}

// Mobileconfig Child security association paramters for an IKEv2 configuration
type childSecurityAssociationParameters struct {
	DiffieHellmanGroup  int    `plist:"DiffieHellmanGroup,omitempty"`
	EncryptionAlgorithm string `plist:"EncryptionAlgorithm,omitempty"`
	IntegrityAlgorithm  string `plist:"IntegrityAlgorithm,omitempty"`
	LifeTimeInMinutes   int    `plist:"LifeTimeInMinutes,omitempty"`
}

// Mobileconfig IPv4 configuration for IKEv2
type ipv4 struct {
	OverridePrimary int `plist:"OverridePrimary"`
}

// Mobileconfig proxy configuration
type proxies struct {
	HTTPEnable  int `plist:"HTTPEnable"`
	HTTPSEnable int `plist:"HTTPSEnable"`
}

// Return a UUID.
func makeUUID() string {
	return strings.ToUpper(uuid.New().String())
}

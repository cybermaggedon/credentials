/****************************************************************************

  Signing (for mobileconfig configuration)

****************************************************************************/

package credentials

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/mastahyeti/cms"
	"io/ioutil"
)

func (client *Client) Sign(payload []byte) ([]byte, error) {

	// ----- Signing key ------

	// Read key file
	raw, err := ioutil.ReadFile(client.signingKey)
	if err != nil {
		return nil, err
	}

	// Parse key for PEM.
	keyPem, _ := pem.Decode([]byte(raw))
	if keyPem == nil {
		return nil, err
	}

	// Parse for ECDSA key.
	key, err := x509.ParseECPrivateKey(keyPem.Bytes)
	if err != nil {
		return nil, err
	}

	// ----- Get signing cert -----

	// Read cert file
	raw, err = ioutil.ReadFile(client.signingCert)
	if err != nil {
		return nil, err
	}

	// Read cert
	certPem, _ := pem.Decode([]byte(raw))
	if certPem == nil {
		return nil, err
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, err
	}

	// ----- Sign -----

	der, err := cms.Sign(payload, []*x509.Certificate{cert}, key)
	if err != nil {
		return nil, err
	}

	return der, nil

}

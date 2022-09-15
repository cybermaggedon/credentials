/****************************************************************************

  Crypto and CKMS support.

****************************************************************************/

package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"google.golang.org/api/cloudkms/v1"
)

// We hash all user IDs to a CKMS key ID.  This function performs the hash.
// This serves two purposes: Key IDs have limited length, and can only contain
// certain characters, and also as CKMS key IDs are public, this makes it
// harder to get the list of email addresses representing TN clients.
func keyId(user string) string {
	h := sha256.New()
	h.Write([]byte("qK^45X/X{{]D!fTinC:"))
	h.Write([]byte(user))
	hash := fmt.Sprintf("%x", h.Sum(nil))
	return hash[0:62]
}

// Decrypt a value using CKMS
func (client *Client) Decrypt(ciphertext []byte) ([]byte, error) {

	// Get cryptoKey ID
	cryptoKey := keyId(client.user)

	// Construct resource name
	template := "projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s"
	keyRing := "user-secrets"
	resourceName := fmt.Sprintf(template, client.project, "global", keyRing,
		cryptoKey)

	// Get CKMS service handle
	svc, err := cloudkms.New(client.client)
	if err != nil {
		return []byte(""), err
	}

	// Decrypt cipher.  Note payload must be base64.
	resp, err := svc.Projects.Locations.KeyRings.CryptoKeys.
		Decrypt(resourceName, &cloudkms.DecryptRequest{
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		}).Do()
	if err != nil {
		return []byte(""), err
	}

	// Decode base64 response.
	plain, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return []byte(""), err
	}

	return plain, nil

}

// Standard decrypt function we use, AES with CTR mode.
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {

	// Construct decrypter
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}

	// IV is the counter.  This is just 138.
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		iv[i] = 0
	}
	iv[15] = 138

	// Ciphertext is big as plaintext.
	plain := make([]byte, len(ciphertext))

	// Construct CTR mode block cipher
	stream := cipher.NewCTR(block, iv)

	// Decrypt
	stream.XORKeyStream(plain, ciphertext)

	return plain, nil

}

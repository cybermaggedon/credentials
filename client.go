// Package providing client-side support for downloading and managing
// Example org credentials.
package credentials

import (
	"encoding/json"
	"errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/people/v1"
	"google.golang.org/api/storage/v1"
	"io/ioutil"
	"net/http"
	"os"
)

// Credentials client
type Client struct {
	client *http.Client

	mcIdentifier  string
	mcName        string
	mcDescription string

	signCredentials bool
	signingKey      string
	signingCert     string

	bucket string

	project string

	user string

	soc string
}

// Create a new credentials client from an HTTP transport.
func NewClient(client *http.Client) (*Client, error) {
	v := &Client{}
	v.client = client

	// Defaults
	v.project = "FIXME-my-example-project"
	v.bucket = "FIXME-my-example-bucket"

	// Default user is my email address
	user, err := v.GetEmailAddress()
	if err != nil {
		return nil, err
	}
	v.user = user

	return v, nil
}

// Create a client handle from service account JSON key
func NewSaClientFromJson(privateJson []byte) (*Client, error) {

	// Create JWT
	config, err := google.JWTConfigFromJSON(privateJson,
		storage.CloudPlatformScope,
		cloudkms.CloudPlatformScope,
		people.UserinfoProfileScope,
		people.UserinfoEmailScope)
	if err != nil {
		return nil, err
	}

	// Create client
	client := config.Client(oauth2.NoContext)

	return NewClient(client)

}

// Create a client handle from service account JSON key
func NewSaClient(path string) (*Client, error) {

	// Open file
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	// Fetch file contents
	raw, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return NewSaClientFromJson(raw)

}

// Read token from local disk
func getTokenFromFile(file string) (*oauth2.Token, error) {

	// Open file
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	// Fetch file contents
	raw, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	return getTokenFromJson(raw)

}

// Convert a raw token to an object (JSON decoder)
func getTokenFromJson(raw []byte) (*oauth2.Token, error) {

	// Get empty OAUTH2 token
	token := &oauth2.Token{}

	// JSON decode token
	err := json.Unmarshal(raw, token)
	if err != nil {
		return nil, err
	}

	return token, nil

}

// Create a credentials client by reading token from a token file.
func NewClientFromTokenFile(file string) (*Client, error) {

	// Fetch the token from the offline storage.
	token, err := getTokenFromFile(file)
	if err != nil {
		return nil, err
	}

	// Get the OAUTH2 config
	config := oauthConfig("")

	// Create a client transport connection using the OAUTH2 token
	client := config.Client(oauth2.NoContext, token)

	return NewClient(client)

}

// Constructs a credentials client from a decoded token object.
func NewClientFromTokenObject(token *oauth2.Token) (*Client, error) {

	// Get the OAUTH2 config
	config := oauthConfig("")

	// Create a client transport connection using the OAUTH2 token
	client := config.Client(oauth2.NoContext, token)

	return NewClient(client)

}

// Constructs a credentials client from a raw token
func NewClientFromToken(raw []byte) (*Client, error) {

	// Fetch the token from the offline storage.
	token, err := getTokenFromJson(raw)
	if err != nil {
		return nil, err
	}

	return NewClientFromTokenObject(token)

}

// Fetch a client user's email address from the People API.
func (client *Client) GetEmailAddress() (string, error) {

	// Create a service handle to the People API.
	svc, err := people.New(client.client)

	// Fetch people/me resource.
	me, err := svc.People.Get("people/me").
		PersonFields("names,emailAddresses").
		Do()
	if err != nil {
		return "", err
	}

	// Error if no email addresses.
	if len(me.EmailAddresses) < 1 {
		return "", errors.New("Your profile has no email addresses")
	}

	// Return first email address.
	email := me.EmailAddresses[0].Value
	return email, nil

}

func (client *Client) SetSoc(id string) {
	client.soc = id
}

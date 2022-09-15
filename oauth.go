/****************************************************************************

  Google OAUTH2 support

****************************************************************************/

package credentials

import (
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/people/v1"
	"google.golang.org/api/storage/v1"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	// Google authentication parameters.
	clientID     = "1041863416400-9ucotql4lgksp8o89krkmia8tkha4ohh.apps.googleusercontent.com"
	clientSecret = "7AyOQH1QAkNCFASyhdNzNIgY"
)

// Chan used to transmit code from HTTP client to main thread
var q chan string

// HTTP callback when OAUTH2 callback is invoked
func oauth2callback(w http.ResponseWriter, r *http.Request) {

	// Get the code from the response
	code := r.FormValue("code")

	// Send code to queue
	q <- code

	// Respond with something human-readable.
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<html><body>Code received, thanks.</body></html>"))

}

// Return a new OAUTH2 config
func oauthConfig(cbUrl string) *oauth2.Config {

	// Return config with app-specific config
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  cbUrl,
		Scopes: []string{
			storage.CloudPlatformScope,
			cloudkms.CloudPlatformScope,
			people.UserinfoProfileScope,
			people.UserinfoEmailScope,
		},
		Endpoint: google.Endpoint,
	}

}

// CLI authentication process.  Outputs a URL to stdout.  The user should
// visit the URL in a browser to authenticate.
func Authenticate(tokenFile string) error {

	// Initialise queue
	q = make(chan string)

	// Register HTTP callback
	http.HandleFunc("/oauth2callback", oauth2callback)

	// Start web server, port 8080.
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			panic(err)
		}
	}()

	// Create OAUTH2 config
	config := oauthConfig("http://localhost:8080/oauth2callback")

	// Construct URL to Google to authenticate.
	url := config.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Println()
	fmt.Println("Visit the URL for the auth dialog:")
	fmt.Println()
	fmt.Println(url)
	fmt.Println()
	fmt.Println("Waiting for authentication...")

	// Wait for code to be provided on queue.
	code := <-q

	fmt.Println("Code received")

	// Handle the exchange code to initiate a transport.
	tok, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return err
	}

	// User should know if there's no refresh token, because this token
	// will expire.
	if tok.RefreshToken == "" {
		fmt.Println("Note: No refresh token, this token will expire.")
	}

	// Create service client.
	client, err := NewClientFromTokenObject(tok)
	if err != nil {
		return err
	}

	// Get email address
	email, err := client.GetEmailAddress()
	if err != nil {
		return err
	}

	// Write token to local file
	f, err := os.Create(tokenFile)
	if err != nil {
		return err
	}
	defer f.Close()
	tokjson, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	f.Write(tokjson)

	// Makes it look like this is successful.
	fmt.Println("Authenticated as", email)

	return nil

}

// Create a client handle from service account JSON key
func saClient(path string) (*http.Client, error) {

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

	// Create JWT
	config, err := google.JWTConfigFromJSON(raw,
		storage.CloudPlatformScope,
		cloudkms.CloudPlatformScope,
		people.UserinfoProfileScope,
		people.UserinfoEmailScope)
	if err != nil {
		return nil, err
	}

	// Create client
	client := config.Client(oauth2.NoContext)

	return client, nil

}

package credentials

import (
	"fmt"
	"os"
)

func Example_authentication() {

	// This is used to do OAUTH2 login and fetch of credential.  It
	// writes a URL to stdout and waits for a browser event, so this
	// should only be performed in a CLI.
	err := Authenticate("output.token.file")
	if err != nil {
		fmt.Println("Error:", err)
	}

}

func Example_list() {

	// Login using a token
	client, err := NewClientFromTokenFile("output.token.file")
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Fetch index
	creds, err := client.GetIndex("fred.bloggs@example.org")

	// Iterate over index
	for _, cred := range creds {
		fmt.Printf("%s: %s\n", cred.GetId(), cred.GetDescription())
	}

}

func Example_fetch() {

	// Get token
	client, err := NewClientFromTokenFile("output.token.file")
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Fetch index
	creds, err := client.GetIndex("fred.bloggs@example.org")

	// This points to the first web credential we find.
	var selected *Credential = nil

	// Search for first web credential
	for _, cred := range creds {
		if cred.GetType() == "web" {
			selected = &cred
			break
		}
	}

	// If no web credential, bail out.
	if selected == nil {
		fmt.Println("No web credential found")
		return
	}

	// List formats supported.  This is overkill for checking web
	// certs support P12 output, but it illustrates format discovery.
	found := false
	fs := (*selected).GetFormats()
	for _, f := range fs {
		fmt.Printf("Format: %s: %s\n", f.Id, f.Description)
		if f.Id == "p12" {
			found = true
		}
	}

	// Check credential supports P12 format.
	if !found {
		fmt.Println("Credential doesn't support P12 format")
		return
	}

	// Get P12 credential.
	payloads, err := (*selected).Get(client, "p12")

	// Iterate over payloads.  For web P12, that's going to be one
	// P12 payload which is written to a file, and one password payload
	// which gets dumped out on stdout.  This demonstrates a more
	// generic approach to disposing of payloads.
	for _, payload := range payloads {

		fmt.Println("Has payload", payload.Id, payload.Description)

		// If payload indicates it should be written to a file,
		// write it to the suggested filename.
		if payload.Disposition == "store" {
			f, _ := os.Create(payload.Filename)
			f.Write(payload.Payload)
			f.Close()
		}

		// If it indicates display, write to output.
		if payload.Disposition == "show" {
			fmt.Println("Value: ", string(payload.Payload))
		}

	}

}

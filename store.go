package credentials

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"google.golang.org/api/pubsub/v1"
	"google.golang.org/api/storage/v1"
	"io"
	"time"
)

// Topic names
const (
	notifyTopic  = "cred-response"
	requestTopic = "cred-request"
)

// Structure for the JSON messages passed to credential manager via pubsub.
type Message struct {

	// Type of request, one of: web, vpn, probe, revoke-web,
	// revoke-vpn, revoke-probe, revoke-all.
	Type string `json:"type,omitempty"`

	// User, in email address format.
	User string `json:"user,omitempty"`

	// Identity string for credential, should be full name for a web
	// certificate, device ID for a VPN cert and probe ID for a probe
	// credential.
	Identity string `json:"identity,omitempty"`

	// For probe credentials, specifies the endpoint to connect to
	// in host:port format.
	Endpoint string `json:"endpoint,omitempty"`

	// For VPN service credentials, specifies the hostname and address
	// allocator.
	Hostname string `json:"hostname,omitempty"`
	Allocator string `json:"allocator,omitempty"`

}

// Structure for JSON messagesreturns from credential manager via pubsub.
type MessageResponse struct {

	// Copy of the message request for which this is a response.
	Message

	// Pub/sub's message ID for the request.
	MessageId string `json:"id"`

	// Whether the request was successful.
	Success bool `json:"success"`
}

// Fetches the credential index for a user, returned as a list of credentials.
func (client *Client) GetIndexVersion(user string) (int64, error) {

	// Get a service handle to GoogleStorage.
	svc, err := storage.New(client.client)
	if err != nil {
		return 0, err
	}

	// Construct pathname to index.
	bucket := client.bucket
	path := user + "/INDEX"

	// Fetch the payload.
	obj, err := svc.Objects.Get(bucket, path).Do()
	if err != nil {
		return 0, err
	}

	return obj.Generation, nil

}

// Fetches the credential index for a user, returned as a list of credentials.
func (client *Client) GetIndex(user string) ([]Credential, error) {

	// Get a service handle to GoogleStorage.
	svc, err := storage.New(client.client)
	if err != nil {
		return nil, err
	}

	// Construct pathname to index.
	bucket := client.bucket
	path := user + "/INDEX"

	// Fetch the payload.
	resp, err := svc.Objects.Get(bucket, path).Download()
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	// Scan the payload, parsing credential objects.
	creds := []Credential{}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {

		// First pass of credential index objects, just to get the type
		// field.
		var ent map[string]string
		err := json.Unmarshal([]byte(scanner.Text()), &ent)
		if err != nil {
			return nil, err
		}

		if ent["type"] == "vpn" {

			// Parse VPN credential index entry.
			cred := &VpnCredential{}
			err := json.Unmarshal([]byte(scanner.Text()), cred)
			if err != nil {
				return nil, err
			}

			// Construct a unique ID from the device name.
			cred.Id = "vpn:" + cred.Device
			cred.User = user
			creds = append(creds, cred)

		} else if ent["type"] == "web" {

			// Parse web credential index entry.
			cred := &WebCredential{}
			err := json.Unmarshal([]byte(scanner.Text()), cred)
			if err != nil {
				return nil, err
			}

			// Construct a unique ID from the bundle name.
			cred.Id = "web:" + cred.Bundle
			cred.User = user
			creds = append(creds, cred)

		} else if ent["type"] == "probe" {

			// Parse probe credential index entry.
			cred := &ProbeCredential{}
			err := json.Unmarshal([]byte(scanner.Text()), cred)
			if err != nil {
				return nil, err
			}

			// Construct a unique ID from the bundle name.
			cred.Id = "probe:" + cred.Bundle
			cred.User = user
			creds = append(creds, cred)

		} else if ent["type"] == "vpn-service" {

			// Parse probe credential index entry.
			cred := &VpnServiceCredential{}
			err := json.Unmarshal([]byte(scanner.Text()), cred)
			if err != nil {
				return nil, err
			}

			// Construct a unique ID from the bundle name.
			cred.Id = "vpn-service:" + cred.Bundle
			cred.User = user
			creds = append(creds, cred)

		} else {

			// Ignore if not VPN and web type.
			fmt.Println("Can't understand type " + ent["type"] + ", ignored.")

		}

	}

	// Error if scanner failed with errors.
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Return creds list.
	return creds, nil

}

// Wrapper function, calls getCredential to get a credential, than fetches the
// content field, and base64-decodes it.
func (client *Client) GetContent(user, credName, key string) ([]byte, error) {

	// Get credential
	cred, err := client.GetCredential(user, credName, key)
	if err != nil {
		return []byte{}, err
	}

	// This object is so we just decode the content field.
	var obj struct {
		Content string `json:"content"`
	}

	// Decode JSON
	err = json.Unmarshal(cred, &obj)
	if err != nil {
		return []byte{}, err
	}

	// De-base64 the string.
	payload, err := base64.StdEncoding.DecodeString(obj.Content)
	return payload, nil

}

// Fetches a decrypted credential payload from the store.
func (client *Client) GetCredential(user, cred, key string) ([]byte, error) {

	// Get GoogleStorage service handle.
	svc, err := storage.New(client.client)
	if err != nil {
		return []byte(""), err
	}

	// Pathname to storage object.
	bucket := client.bucket
	path := user + "/" + cred

	// Get object.
	resp, err := svc.Objects.Get(bucket, path).Download()
	if err != nil {
		return []byte(""), err
	}

	// Get object as string.
	buf := bytes.NewBufferString("")
	io.Copy(buf, resp.Body)
	resp.Body.Close()

	// Decode the hexbin encoding on the key.
	rawkey := make([]byte, len(key)/2)
	_, err = hex.Decode(rawkey, []byte(key))

	// Decrypt key using CKMS.
	key7, err := client.Decrypt(rawkey)
	if err != nil {
		return []byte(""), err
	}

	// Undo hexbin encoding on ciphertext.
	ciph := make([]byte, len(buf.String())/2)
	_, err = hex.Decode(ciph, []byte(buf.String()))
	if err != nil {
		return []byte(""), err
	}

	// Decrypt using AES.
	plain, err := decrypt(ciph, key7)
	if err != nil {
		return []byte(""), err
	}

	// Return plaintext.
	return plain, nil

}

// Requests a web credential creation to the credential manager.
func (client *Client) CreateWebCredential(user, identity string) error {

	m := Message{
		Type:     "web",
		User:     user,
		Identity: identity,
	}

	msg, _ := json.Marshal(&m)

	err := client.invokeCredentialManager(string(msg))
	if err != nil {
		return err
	}

	return nil

}

// Requests a VPN credential creation to the credential manager.
func (client *Client) CreateVpnCredential(user, identity string) error {

	m := Message{
		Type:     "vpn",
		User:     user,
		Identity: identity,
	}

	msg, _ := json.Marshal(&m)

	err := client.invokeCredentialManager(string(msg))
	if err != nil {
		return err
	}

	return nil

}

// Requests a probe credential creation to the credential manager.
func (client *Client) CreateProbeCredential(user, identity, endp string) error {

	m := Message{
		Type:     "probe",
		User:     user,
		Identity: identity,
		Endpoint: endp,
	}

	msg, _ := json.Marshal(&m)

	err := client.invokeCredentialManager(string(msg))
	if err != nil {
		return err
	}

	return nil

}

// Requests a VPN credential creation to the credential manager.
func (client *Client) CreateVpnServiceCredential(user, identity, hostname,
	allocator string) error {

	m := Message{
		Type:     "vpn-service",
		User:     user,
		Identity: identity,
		Hostname: hostname,
		Allocator: allocator,
	}

	msg, _ := json.Marshal(&m)

	err := client.invokeCredentialManager(string(msg))
	if err != nil {
		return err
	}

	return nil

}

// Requests a web credential revocation to the credential manager.
func (client *Client) RevokeWebCredential(user, identity string) error {

	m := Message{
		Type:     "revoke-web",
		User:     user,
		Identity: identity,
	}

	msg, _ := json.Marshal(&m)

	err := client.invokeCredentialManager(string(msg))
	if err != nil {
		return err
	}

	return nil

}

// Requests a VPN credential revocation to the credential manager.
func (client *Client) RevokeVpnCredential(user, identity string) error {

	m := Message{
		Type:     "revoke-vpn",
		User:     user,
		Identity: identity,
	}

	msg, _ := json.Marshal(&m)

	err := client.invokeCredentialManager(string(msg))
	if err != nil {
		return err
	}

	return nil

}

// Requests a VPN credential revocation to the credential manager.
func (client *Client) RevokeVpnServiceCredential(user, identity string) error {

	m := Message{
		Type:     "revoke-vpn-service",
		User:     user,
		Identity: identity,
	}

	msg, _ := json.Marshal(&m)

	err := client.invokeCredentialManager(string(msg))
	if err != nil {
		return err
	}

	return nil

}

// Requests a probe credential revocation to the credential manager.
func (client *Client) RevokeProbeCredential(user, identity string) error {

	m := Message{
		Type:     "revoke-probe",
		User:     user,
		Identity: identity,
	}

	msg, _ := json.Marshal(&m)

	err := client.invokeCredentialManager(string(msg))
	if err != nil {
		return err
	}

	return nil

}

// Requests revocation of all credentials belonging to a user.
func (client *Client) RevokeAll(user string) error {

	m := Message{
		Type: "revoke-all",
		User: user,
	}

	msg, _ := json.Marshal(&m)

	err := client.invokeCredentialManager(string(msg))
	if err != nil {
		return err
	}

	return nil

}

// Publish a message a return response.
func (client *Client) invokeCredentialManager(msg string) error {

	// Project name.
	pr := client.project

	// Get a service handle to GoogleStorage.
	svc, err := pubsub.New(client.client)
	if err != nil {
		return err
	}

	var reqTopic string
	var resTopic string

	if client.soc == "" {
		reqTopic = requestTopic
		resTopic = notifyTopic
	} else {
		reqTopic = requestTopic + "-" + client.soc
		resTopic = notifyTopic + "-" + client.soc
	}

	// Create topics.  They should exist already.
	err = maybeCreateTopic(svc, pr, reqTopic)
	if err != nil {
		return err
	}
	err = maybeCreateTopic(svc, pr, resTopic)
	if err != nil {
		return err
	}

	// Make subscription name - resource must start with a letter.
	subscription := "s" + makeUUID()
	subsName := "projects/" + pr + "/subscriptions/" + subscription

	// Notification topic.
	resName := "projects/" + pr + "/topics/" + resTopic

	// Create subscription.
	s := &pubsub.Subscription{
		Name:  subsName,
		Topic: resName,
	}
	_, err = svc.Projects.Subscriptions.Create(subsName, s).
		Do()
	if err != nil {
		return err
	}

	// Delete subscription if we exit.
	defer svc.Projects.Subscriptions.Delete(subsName).Do()

	// Encode message base64.
	encoded := base64.StdEncoding.EncodeToString([]byte(msg))

	// Publish.
	pubreq := &pubsub.PublishRequest{
		Messages: []*pubsub.PubsubMessage{
			&pubsub.PubsubMessage{
				Data: encoded,
			},
		},
	}
	reqName := "projects/" + pr + "/topics/" + reqTopic

	resp, err := svc.Projects.Topics.Publish(reqName, pubreq).
		Do()
	if err != nil {
		return err
	}

	fmt.Println("Request submitted, waiting...")

	// Get messageID.  If none, something is wrong.
	if len(resp.MessageIds) < 1 {
		return errors.New("Array too short, shouldn't happen.")
	}
	id := resp.MessageIds[0]

	// Give up after 30 seconds.
	giveUp := time.Now().Add(time.Second * 30)

	// Receive loop, wait for response message.
	done := false
	for !done {

		// Pull next message.
		resp, err := svc.Projects.Subscriptions.Pull(subsName,
			&pubsub.PullRequest{
				MaxMessages:       1,
				ReturnImmediately: true,
			}).Do()
		if err != nil {
			return err
		}

		// Loop through all (1) messages...
		for _, m := range resp.ReceivedMessages {

			// Decode base64.
			var msgr MessageResponse
			data, _ :=
				base64.StdEncoding.DecodeString(m.Message.Data)

			// Decode JSON.
			err = json.Unmarshal([]byte(data), &msgr)
			if err != nil {
				fmt.Println("Garbage message, ignored.")
				continue
			}

			// Check message ID, should be the one we're waiting
			// for.
			if msgr.MessageId == id {
				if msgr.Success {
					fmt.Println("Success.")
				} else {
					fmt.Println("Failed.")
					return errors.New("Failed.")
				}
				done = true
				continue
			}

		}

		// Give up if we wait too long.
		if time.Now().After(giveUp) {
			fmt.Println("No response received, giving up.")
			done = true
		}

		// Sleep and retry
		time.Sleep(time.Second * 1)

	}

	return nil

}

// Set the mobileconfig identifier.
func (client *Client) SetMcIdentifier(val string) *Client {
	client.mcIdentifier = val
	return client
}

// Set the mobileconfig name.
func (client *Client) SetMcName(val string) *Client {
	client.mcName = val
	return client
}

// Set the mobileconfig description.
func (client *Client) SetMcDescription(val string) *Client {
	client.mcDescription = val
	return client
}

// Create a topic if it doesn't already exist.
func maybeCreateTopic(svc *pubsub.Service, pr, topic string) error {

	// Topic name.
	name := "projects/" + pr + "/topics/" + topic

	// Get the topic
	_, err := svc.Projects.Topics.Get(name).Do()
	if err == nil {

		// Already exists, then we're done.
		return nil

	}

	// Error... assume it doesn't exist.  If the error was because of
	// something else, that will become apparent shortly.

	// Create the topic.
	_, err = svc.Projects.Topics.Create(
		name,
		&pubsub.Topic{
			Name: name,
		}).Do()
	if err != nil {
		// Create failed.
		fmt.Println("Topic create failed.")
		return err
	}

	return nil

}

// Set signing parameters for a mobileconfig.
func (c *Client) SetSigning(signingKeyFile, signingCertFile string) *Client {
	c.signCredentials = true
	c.signingKey = signingKeyFile
	c.signingCert = signingCertFile
	return c
}

// Set client username.  All client actions will be performed against the
// credential store belonging to this user.  You will need administration
// privileges to operate on another user's credential store.
func (c *Client) SetUser(user string) *Client {
	c.user = user
	return c
}

// Set the cloud project name to use.
func (c *Client) SetProject(project string) *Client {
	c.project = project
	return c
}

// Set the credential bucket to use.
func (c *Client) SetBucket(bucket string) *Client {
	c.bucket = bucket
	return c
}

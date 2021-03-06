package chatbackend

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"log/syslog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	panthalassaKeyManager "github.com/Bit-Nation/panthalassa/keyManager"
	panthalassaKeyStore "github.com/Bit-Nation/panthalassa/keyStore"
	panthalassaMnemonic "github.com/Bit-Nation/panthalassa/mnemonic"
	panthalassaProfile "github.com/Bit-Nation/panthalassa/profile"
	backendProtobuf "github.com/Bit-Nation/protobuffers"
	bitnationX3dh "github.com/Bit-Nation/x3dh"
	golangProto "github.com/golang/protobuf/proto"
	gorillaWebSocket "github.com/gorilla/websocket"
	uuid "github.com/satori/go.uuid"
	testifyRequire "github.com/stretchr/testify/require"
	tiabcDoubleratchet "github.com/tiabc/doubleratchet"
	cryptoEd25519 "golang.org/x/crypto/ed25519"
)

type Client struct {
	Profile             *panthalassaProfile.Profile
	Mnemonic            panthalassaMnemonic.Mnemonic
	KeyManager          panthalassaKeyManager.KeyManager
	SignedPreKey        bitnationX3dh.KeyPair
	OneTimePreKeys      []bitnationX3dh.KeyPair
	WebSocketConnection *gorillaWebSocket.Conn
}

func TestHandleWebSocketConnection(t *testing.T) {
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("STARTING TESTS"))
	} // if production == ""
	// Get the port on which the chat backend should be listening on
	listenPort := os.Getenv("PORT")
	// Start the websocket server
	go StartWebSocketServer()
	// Wait just a bit for the web socket to actually initialise before trying to connect to it
	time.Sleep(1 * time.Second)
	// Create a new static SignedPreKey to make testing easier
	signedPreKeyReceiver := newStaticSignedPreKeyReceiver()
	// Create a new static OneTimePreKey to make testing easier
	oneTimePreKeysReceiver := newStaticOneTimePreKeysReceiver()
	// Create a new client receiver
	clientReceiver := newClient(
		t,
		"Receiver",
		"Earth",
		"base64",
		"amazing surprise admit live basic outside people echo fault come interest flat awesome dragon share reason suggest scatter project omit daring business push afford",
		"ws://127.0.0.1:" + listenPort + "/chat",
		"super_secure_over_9000",
		oneTimePreKeysReceiver,
		signedPreKeyReceiver,
	)
	clientReceiverRestartedApp := newClient(
		t,
		"Receiver",
		"Earth",
		"base64",
		"amazing surprise admit live basic outside people echo fault come interest flat awesome dragon share reason suggest scatter project omit daring business push afford",
		"ws://127.0.0.1:" + listenPort + "/chat",
		"super_secure_over_9000",
		oneTimePreKeysReceiver,
		signedPreKeyReceiver,
	)
	// Create a new client sender
	clientSender := newClient(
		t,
		"Sender",
		"Earth",
		"base64",
		"crunch ahead select guess pledge bundle midnight gossip episode govern brick humor forest age inhale scatter fringe love brief cute since room orange couple",
		"ws://127.0.0.1:" + listenPort + "/chat",
		"super_secure_over_9000",
		[]bitnationX3dh.KeyPair{},
		bitnationX3dh.KeyPair{},
	)
	// Upload a profile on the backend
	time.Sleep(7 * time.Second)
	putProfileOnBackend(t)
	// Retreive a profile from the backend
	getProfileFromBackend(t)
	// Reciever needs to pass authentication
	//clientReceiver.testAuth(t)
	// Receiver uploads the one time pre keys
	clientReceiver.testUploadOneTimePreKeys(t)
	// Receiver uploads the signed pre key
	clientReceiver.testUploadSignedPreKey(t)

	// Receiver receives any real time messages while he is online
	go func() {
		if production == "" {
			logError(syslog.LOG_INFO, errors.New(hex.EncodeToString(clientReceiver.Profile.Information.IdentityPubKey)+" *C 1* Waiting for real time messages"))
		} // if production == ""
		// Listen for real time messages, will block untill messages arrive
		unreadChatMessages := clientReceiver.receiveUndeliveredMessages(t)
		if production == "" {
			logError(syslog.LOG_INFO, errors.New(hex.EncodeToString(clientReceiver.Profile.Information.IdentityPubKey)+" *C 1* Successfully received real time messages"))
		} // if production == ""
		// Test if we can decrypt the message successfully
		expectedDecryptedMessages := []string{"SECRETMESSAGENEW1", "SECRETMESSAGENEW1", "SECRETMESSAGENEW1"}
		// For each message that we want to read
		for index, unreadChatMessage := range unreadChatMessages {
			// Try to decrypt them and read them
			clientReceiver.testReadDoubleRatchetMessages(t, unreadChatMessage, expectedDecryptedMessages[index])
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(hex.EncodeToString(clientReceiver.Profile.Information.IdentityPubKey)+" *C 1* Successfully decrypted and read real time messages : "+strconv.Itoa(index+1)))
			} // if production == ""
		} // for index, unreadChatMessage
		// Close connection on purpose to test message exchange while client is offline
		if production == "" {
			logError(syslog.LOG_INFO, errors.New(hex.EncodeToString(clientReceiver.Profile.Information.IdentityPubKey)+" *C 1* Going offline on purpose to test receiving persisted messages"))
		} // if production == ""
		clientReceiver.WebSocketConnection.Close()
	}()

	// Initial message sender needs to pass authentication
	//clientSender.testAuth(t)
	// Get a hex decoded byte representation of the identity public key for the initial message receiver that we want to chat with
	identityPublicKeyBytes, identityPublicKeyBytesErr := hex.DecodeString("22cfd1af5798544287cbf7721a0a4ebc2506d6f4df05413355a7f5cc86740724")
	testifyRequire.Nil(t, identityPublicKeyBytesErr)
	// Initial message sender needs to request the pre key bundle of the receiver
	remotePreKeyBundlePublic := clientSender.testRequestPreKeyBundle(t, identityPublicKeyBytes)
	// Initial message sender sends a message to the backend to get persisted
	clientSender.testSendMessage(t, remotePreKeyBundlePublic)
	// Allow a bit of time for the real time message to be read and for the client to disconnect on purpose so we can test the offline one
	time.Sleep(5 * time.Second)
	// Initial message sender sends a message to the backend to get persisted
	clientSender.testSendMessage(t, remotePreKeyBundlePublic)
	// Receiver needs to pass auth again
	//clientReceiverRestartedApp.testAuth(t)
	// Receiver receives any undelivered messages while he was offline
	unreadChatMessages := clientReceiverRestartedApp.receiveUndeliveredMessages(t)
	// Test if we can decrypt the message successfully
	expectedDecryptedMessages := []string{"SECRETMESSAGENEW1", "SECRETMESSAGENEW1", "SECRETMESSAGENEW1"}
	// For each message that we want to read
	for index, unreadChatMessage := range unreadChatMessages {
		// Try to decrypt them and read them
		clientReceiverRestartedApp.testReadDoubleRatchetMessages(t, unreadChatMessage, expectedDecryptedMessages[index])
		if production == "" {
			logError(syslog.LOG_INFO, errors.New(hex.EncodeToString(clientReceiverRestartedApp.Profile.Information.IdentityPubKey)+" *C 2* Successfully decrypted and read persisted messages : "+strconv.Itoa(index+1)))
		} // if production == ""
	} // for index, unreadChatMessage
	// Leave some time for the background tasks to finish
	time.Sleep(30 * time.Second)
} // func TestHandleWebSocketConnection

// Test persisting a static profile to the backend
func putProfileOnBackend(t *testing.T) {
	// Get the port on which the chat backend should be listening on
	listenPort := os.Getenv("PORT")
	// Use an already base64 encoded Profile protobuf bytes to make testing simpler
	profileBase64 := strings.NewReader(`CgNCb2ISBUVhcnRoGgZiYXNlNjQiICLP0a9XmFRCh8v3choKTrwlBtb03wVBM1Wn9cyGdAckKiECcFb7RfrdatrDp9TlXw1/nNU/cF1hoxaMCoEPY1a7c8QyIH7ffl1cs/4+0WzRS7j7c+Y2/moLUj0iLxgLKbqakcphOLTasdoFQAJKQDztvodZmPkxuEBra1RGXsMsyirTIajSuaN4rOoNMkOPB/8+RXFZKVOhkjkNTsSW+WU7dYExiaxC8Wi7KVOB5wNSQaxE7LN3oNBk1GUkmyYFaN5fWrYmTDe9iz39gWH6/gCLVuFwA1g4RpMnNoiD0rdIC+9AL6gUC8XMQKZuuKOY/QcB`)
	// Create a new PUT request to put the profile in the storage
	httpRequest, httpRequestErr := http.NewRequest("PUT", "http://127.0.0.1:" + listenPort + "/profile", profileBase64)
	testifyRequire.Nil(t, httpRequestErr)
	// Set bearer auth
	httpRequest.Header.Set("Bearer", "super_secure_over_9000")
	// Set the identityPublicKey of the person who owns the profile
	httpRequest.Header.Set("Identity", "22cfd1af5798544287cbf7721a0a4ebc2506d6f4df05413355a7f5cc86740724")
	// Set the content type
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Make the http request
	backendResponse, backendResponseErr := http.DefaultClient.Do(httpRequest)
	testifyRequire.Nil(t, backendResponseErr)
	// If there is a more descriptive error, it will be contained in the response body
	backendResponseBody, readErr := ioutil.ReadAll(backendResponse.Body)
	testifyRequire.Nil(t, readErr)
	// An empty response body means all is well
	testifyRequire.Equal(t, []byte{}, backendResponseBody)
	// Make sure that all went well
	testifyRequire.Equal(t, "200 OK", backendResponse.Status)
	defer backendResponse.Body.Close()
} // func putProfileOnBackend

// Test getting an already persisted profile from the backend
func getProfileFromBackend(t *testing.T) {
	// Get the port on which the chat backend should be listening on
	listenPort := os.Getenv("PORT")
	// Use an already base64 encoded Profile protobuf bytes to make testing simpler
	profileBase64 := `CgNCb2ISBUVhcnRoGgZiYXNlNjQiICLP0a9XmFRCh8v3choKTrwlBtb03wVBM1Wn9cyGdAckKiECcFb7RfrdatrDp9TlXw1/nNU/cF1hoxaMCoEPY1a7c8QyIH7ffl1cs/4+0WzRS7j7c+Y2/moLUj0iLxgLKbqakcphOLTasdoFQAJKQDztvodZmPkxuEBra1RGXsMsyirTIajSuaN4rOoNMkOPB/8+RXFZKVOhkjkNTsSW+WU7dYExiaxC8Wi7KVOB5wNSQaxE7LN3oNBk1GUkmyYFaN5fWrYmTDe9iz39gWH6/gCLVuFwA1g4RpMnNoiD0rdIC+9AL6gUC8XMQKZuuKOY/QcB`
	// Decode the base64 and get the pure Profile protobuf bytes
	profileProtobufBytes, profileProtobufErr := base64.StdEncoding.DecodeString(profileBase64)
	testifyRequire.Nil(t, profileProtobufErr)
	// Create a new get request to get a profile from the backend
	httpRequest, httpRequestErr := http.NewRequest("GET", "http://127.0.0.1:" + listenPort + "/profile", nil)
	testifyRequire.Nil(t, httpRequestErr)

	// Set bearer auth
	httpRequest.Header.Set("Bearer", "super_secure_over_9000")
	// Set the identityPublicKey of the person who owns the profile
	httpRequest.Header.Set("Identity", "22cfd1af5798544287cbf7721a0a4ebc2506d6f4df05413355a7f5cc86740724")
	// Set the content type
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Make the http request
	backendResponse, backendResponseErr := http.DefaultClient.Do(httpRequest)
	testifyRequire.Nil(t, backendResponseErr)
	// Read the base64 Profile protobuf bytes from the backend
	profileBackendBase64, readErr := ioutil.ReadAll(backendResponse.Body)
	testifyRequire.Nil(t, readErr)
	// Decode the base64 Profile protobuf bytes to get the actual Profile protobuf bytes
	profileBackend, profileErr := base64.StdEncoding.DecodeString(string(profileBackendBase64))
	testifyRequire.Nil(t, profileErr)
	// Make sure that the base64 decoded bytes are the same with the base64 decoded Profile protobuf bytes that the backend returns
	testifyRequire.Equal(t, profileProtobufBytes, profileBackend)
	// Close the response body after the function ends
	defer backendResponse.Body.Close()
	// Wait for any background operations to complete
	time.Sleep(5 * time.Second)
} // func getProfileFromBackend(t *testing.T)

func newStaticSignedPreKeyReceiver() bitnationX3dh.KeyPair {
	// Static SignedPreKey to make it easier for testing
	signedPreKeyReceiver := bitnationX3dh.KeyPair{}
	signedPreKeyReceiver.PublicKey = [32]byte{224, 145, 192, 31, 248, 20, 4, 238, 131, 116, 219, 3, 105, 218, 251, 88, 136, 64, 31, 86, 188, 112, 29, 15, 255, 88, 111, 51, 47, 155, 0, 73}
	signedPreKeyReceiver.PrivateKey = [32]byte{72, 26, 177, 188, 146, 165, 221, 228, 180, 107, 65, 34, 68, 102, 103, 219, 49, 123, 99, 163, 73, 2, 163, 64, 37, 243, 197, 12, 230, 18, 110, 86}
	return signedPreKeyReceiver
}

func newStaticOneTimePreKeysReceiver() []bitnationX3dh.KeyPair {
	// Static OneTimePreKey to make it easier for testing
	oneTimePreKeyReceiver := bitnationX3dh.KeyPair{}
	oneTimePreKeyReceiver.PublicKey = [32]byte{152, 92, 130, 237, 124, 95, 40, 165, 218, 47, 160, 237, 178, 113, 53, 115, 166, 209, 228, 195, 23, 218, 116, 73, 84, 3, 74, 34, 215, 150, 216, 78}
	oneTimePreKeyReceiver.PrivateKey = [32]byte{224, 29, 132, 210, 252, 220, 252, 165, 131, 176, 96, 173, 180, 208, 196, 171, 229, 56, 241, 237, 59, 86, 164, 13, 253, 102, 55, 158, 168, 123, 81, 101}
	return []bitnationX3dh.KeyPair{oneTimePreKeyReceiver}
}

func newWebSocketConnection(t *testing.T, websocketURL, bearer, identity string) *gorillaWebSocket.Conn {
	// Setup custom headers to allow the Bearer token
	customHeaders := http.Header{}
	// Add the Bearer token to the custom headers
	customHeaders.Add("Bearer", bearer)
	customHeaders.Add("Identity", identity)
	// Initialize a websocket dialer
	websocketDialer := gorillaWebSocket.Dialer{}
	// Initialize a websocket connection of a message sender
	websocketConnection, websocketConnectionResponse, websocketConnectionErr := websocketDialer.Dial(websocketURL, customHeaders)
	// Check if we have a valid object first to avoid panic
	if websocketConnectionResponse != nil {
		// Read the response from the websocket package which should contain debug info in case of error
		websocketConnectionResponseBody, readErr := ioutil.ReadAll(websocketConnectionResponse.Body)
		testifyRequire.Nil(t, readErr)
		testifyRequire.Equal(t, []byte{}, websocketConnectionResponseBody)
	}
	testifyRequire.Nil(t, websocketConnectionErr)
	return websocketConnection
}
func newClient(t *testing.T, name, location, image, mnemonicString, websocketURL, bearer string, oneTimePreKeys []bitnationX3dh.KeyPair, signedPreKey bitnationX3dh.KeyPair) Client {
	// Use the mnemonic string supplied
	mnemonic, mnemonicErr := panthalassaMnemonic.FromString(mnemonicString)
	testifyRequire.Nil(t, mnemonicErr)
	// Create a new keystore from the mnemonic
	keyStore, keystoreErr := panthalassaKeyStore.NewFromMnemonic(mnemonic)
	testifyRequire.Nil(t, keystoreErr)
	// Create a new keymanager using the keyStore
	keyManager := panthalassaKeyManager.CreateFromKeyStore(keyStore)
	// Establish a new websocket connection
	identityPublicKeySenderHex, identityPublicKeySenderHexErr := keyManager.IdentityPublicKey()
	testifyRequire.Nil(t, identityPublicKeySenderHexErr)
	bearerTokenSignature, bearerTokenSignatureErr := keyManager.IdentitySign([]byte(bearer))
	testifyRequire.Nil(t, bearerTokenSignatureErr)
	websocketConnection := newWebSocketConnection(t, websocketURL, base64.StdEncoding.EncodeToString(bearerTokenSignature), identityPublicKeySenderHex)
	// Create a signed version of the profile
	profileSigned, profileErr := panthalassaProfile.SignProfile(name, location, image, *keyManager)
	testifyRequire.Nil(t, profileErr)
	// Create a new client object
	client := Client{}
	// Set the Mnemonic
	client.Mnemonic = mnemonic
	// Set the KeyManager
	client.KeyManager = *keyManager
	// Set the Profile
	client.Profile = profileSigned
	// Set the OneTimePreKeys
	client.OneTimePreKeys = oneTimePreKeys
	// Set the SignedPreKey
	client.SignedPreKey = signedPreKey
	// Set the WebSocketCOnnection
	client.WebSocketConnection = websocketConnection
	// Return a client object containing all of the set values
	return client
} // func newClient

func (c *Client) testUploadOneTimePreKeys(t *testing.T) {
	messageFromBackend := backendProtobuf.BackendMessage{}
	// Initialize our Message structure to send a request to the backend
	messageToBackendProtobuf := backendProtobuf.BackendMessage{}
	// Initialize an empty Response structure
	messageToBackendProtobuf.Response = &backendProtobuf.BackendMessage_Response{}
	// Add the request id
	messageToBackendProtobuf.RequestID = uuid.NewV4().String()
	// For each oneTimePreKey
	for _, oneTimePreKey := range c.OneTimePreKeys {
		// Initialize an empty PreKey structure
		preKeyProtobuf := backendProtobuf.PreKey{}
		// Set the Key field in the PreKey structure to the PublicKey from the oneTimePreKey bitnationX3dh.KeyPair
		preKeyProtobuf.Key = oneTimePreKey.PublicKey[:]
		// Set the IdentityKey in PreKey structure to the IdentityPubKey in the Client profile
		preKeyProtobuf.IdentityKey = c.Profile.Information.IdentityPubKey
		// Set a fix timestamp of the oneTimePreKey
		// @TODO find out if this timestamp is fixed and related to oneTimePreKey creation time
		preKeyProtobuf.TimeStamp = time.Now().UnixNano()
		// Sign the IdentityKey with the KeyManager of the client
		identityKeySignature, identityKeySignatureErr := c.KeyManager.IdentitySign(preKeyProtobuf.IdentityKey)
		testifyRequire.Nil(t, identityKeySignatureErr)
		// Set the IdentityKeySignature in the PreKey structure to the resulting signature of the IdentitySign process
		preKeyProtobuf.IdentityKeySignature = identityKeySignature
		// Append the PreKey structure to the message response we are about to send to the backend
		messageToBackendProtobuf.Response.OneTimePrekeys = append(messageToBackendProtobuf.Response.OneTimePrekeys, &preKeyProtobuf)
	} // for _, oneTimePreKey := range c.OneTimePreKeys
	// Use protobuf to marshal the message response we are about to send
	messageToBackendProtobufBytes, messageToBackendProtobufBytesErr := golangProto.Marshal(&messageToBackendProtobuf)
	testifyRequire.Nil(t, messageToBackendProtobufBytesErr)
	// Send the message over the websocket connection
	writeMessageError := c.WebSocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToBackendProtobufBytes)
	testifyRequire.Nil(t, writeMessageError)
	_, messageFromBackendProtobufBytes, readMessageErr := c.WebSocketConnection.ReadMessage()
	testifyRequire.Nil(t, readMessageErr)
	protoUnmarshalErr := golangProto.Unmarshal(messageFromBackendProtobufBytes, &messageFromBackend)
	testifyRequire.Nil(t, protoUnmarshalErr)
	testifyRequire.Equal(t, "", messageFromBackend.Error)
	testifyRequire.Equal(t, messageFromBackend.RequestID, messageToBackendProtobuf.RequestID)
} // testUploadOneTimePreKeys

func (c *Client) testUploadSignedPreKey(t *testing.T) {
	messageFromBackend := backendProtobuf.BackendMessage{}
	// Initialize our Message structure to send a request to the backend
	messageToBackendProtobuf := backendProtobuf.BackendMessage{}
	// Add the request id
	messageToBackendProtobuf.RequestID = uuid.NewV4().String()
	// Initialize an empty Response structure
	messageToBackendProtobuf.Request = &backendProtobuf.BackendMessage_Request{}
	// Initialize an empty PreKey structure
	preKeyProtobuf := backendProtobuf.PreKey{}
	// Set the Key field in the PreKey structure to the PublicKey from the signedPreKey bitnationX3dh.KeyPair
	preKeyProtobuf.Key = c.SignedPreKey.PublicKey[:]
	// Set the IdentityKey in PreKey structure to the IdentityPubKey in the Client profile
	preKeyProtobuf.IdentityKey = c.Profile.Information.IdentityPubKey
	// Set a fix timestamp of the signedPreKey
	// @TODO find out if this timestamp is fixed and related to signedPreKey creation time
	preKeyProtobuf.TimeStamp = time.Now().UnixNano()
	// Sign the IdentityKey with the KeyManager of the client
	identityKeySignature, identityKeySignatureErr := c.KeyManager.IdentitySign(preKeyProtobuf.IdentityKey)
	testifyRequire.Nil(t, identityKeySignatureErr)
	// Set the IdentityKeySignature in the PreKey structure to the resulting signature of the IdentitySign process
	preKeyProtobuf.IdentityKeySignature = identityKeySignature
	// Append the PreKey structure to the message response we are about to send to the backend
	messageToBackendProtobuf.Request.NewSignedPreKey = &preKeyProtobuf
	// Use protobuf to marshal the message response we are about to send
	messageToBackendProtobufBytes, messageToBackendProtobufBytesErr := golangProto.Marshal(&messageToBackendProtobuf)
	testifyRequire.Nil(t, messageToBackendProtobufBytesErr)
	// Send the message over the websocket connection
	writeMessageError := c.WebSocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToBackendProtobufBytes)
	testifyRequire.Nil(t, writeMessageError)
	// Read the response from the backend
	_, messageFromBackendProtobufBytes, readMessageErr := c.WebSocketConnection.ReadMessage()
	testifyRequire.Nil(t, readMessageErr)
	protoUnmarshalErr := golangProto.Unmarshal(messageFromBackendProtobufBytes, &messageFromBackend)
	testifyRequire.Nil(t, protoUnmarshalErr)
	testifyRequire.Equal(t, "", messageFromBackend.Error)
	testifyRequire.Equal(t, messageFromBackend.RequestID, messageToBackendProtobuf.RequestID)
} // testUploadSignedPreKey

func (c *Client) testSendMessage(t *testing.T, receiverPreKeyBundlePublic PreKeyBundlePublic) {
	messageFromBackend := backendProtobuf.BackendMessage{}
	// Initialize our Message structure to send a request to the backend
	messageToBackendProto := backendProtobuf.BackendMessage{}
	// Set a request id
	messageToBackendProto.RequestID = uuid.NewV4().String()
	// Initialize an empty Request structure
	messageToBackendProto.Request = &backendProtobuf.BackendMessage_Request{}
	// Create a key store for the message Sender using the mnemonic from the client
	keyStoreSender, keystoreSenderErr := panthalassaKeyStore.NewFromMnemonic(c.Mnemonic)
	testifyRequire.Nil(t, keystoreSenderErr)
	// Create a new keyManager for the message Sender using the created key store
	keyManagerSender := panthalassaKeyManager.CreateFromKeyStore(keyStoreSender)
	// Get the message Sender chat id key pair
	chatIDKeyPairSender, chatIDKeyPairErr := keyManagerSender.ChatIdKeyPair()
	testifyRequire.Nil(t, chatIDKeyPairErr)
	// Get the message Sender identity public key
	identityPublicKeySenderHex, identityPublicKeySenderHexErr := keyManagerSender.IdentityPublicKey()
	testifyRequire.Nil(t, identityPublicKeySenderHexErr)
	// Create a new 25519 curve for the message Sender
	curveSender := bitnationX3dh.NewCurve25519(rand.Reader)
	// Create a new x3dh for Sender using the 25519 curve and the message Sender chat id key pair
	x3dhSender := bitnationX3dh.New(&curveSender, sha256.New(), "testing", chatIDKeyPairSender)
	// Initialize xh3d protocol from the Sender side
	initializedX3DHProtocolSender, initializedX3DHProtocolErr := x3dhSender.CalculateSecret(&receiverPreKeyBundlePublic)
	testifyRequire.Nil(t, initializedX3DHProtocolErr)
	// Use the calculated shared secret which is a result from consuming the message Receiver's prekey bundle
	sharedSecretSender := initializedX3DHProtocolSender.SharedSecret
	// Initialize a new double Ratchet session for Sender which would allow her to encrypt a message
	var drSharedSec tiabcDoubleratchet.Key
	copy(drSharedSec[:], sharedSecretSender[:])
	doubleRatchetSessionSender, doubleRatchetSessionErr := tiabcDoubleratchet.New(drSharedSec, doubleratchetKeyPair{keyPair: chatIDKeyPairSender}, tiabcDoubleratchet.WithKeysStorage(&tiabcDoubleratchet.KeysStorageInMemory{}))
	testifyRequire.Nil(t, doubleRatchetSessionErr)
	// Encrypt a message from the message Sender
	doubleRatchetMsgSender := doubleRatchetSessionSender.RatchetEncrypt([]byte("SECRETMESSAGENEW1"), []byte{})
	// Initialize a protobuf structure to store the double Ratchet msg from the message Sender
	protobufDoubleRatchetMsgSender := backendProtobuf.DoubleRatchetMsg{}
	// Set the double ratchet public key
	protobufDoubleRatchetMsgSender.DoubleRatchetPK = doubleRatchetMsgSender.Header.DH[:]
	// Set the encrypted message
	protobufDoubleRatchetMsgSender.CipherText = doubleRatchetMsgSender.Ciphertext
	// Set the number of the message in the sending chain
	protobufDoubleRatchetMsgSender.N = doubleRatchetMsgSender.Header.N
	// Set the length of the previous sending chain
	protobufDoubleRatchetMsgSender.Pn = doubleRatchetMsgSender.Header.PN
	// Initialize a protobuf structure which would contain our previously created DoubleRatchetMsg{}
	chatMessageSender := backendProtobuf.ChatMessage{}
	// Set the OneTimePreKey to the message Receiver OneTimePreKey from his PreKeyBundle
	chatMessageSender.OneTimePreKey = receiverPreKeyBundlePublic.BundleOneTimePreKey[:]
	// Set the SignedPreKey to the message Receiver SignedPreKey from his PreKeyBundle
	chatMessageSender.SignedPreKey = receiverPreKeyBundlePublic.BundleSignedPreKey[:]
	// Set the EphemeralKey to the message Receiver EphemeralKey from his PreKeyBundle
	chatMessageSender.EphemeralKey = initializedX3DHProtocolSender.EphemeralKey[:]
	// Sign the EphemeralKey of the message Sender
	senderEphemeralKeySignature, senderEphemeralKeySignatureErr := keyManagerSender.IdentitySign(chatMessageSender.EphemeralKey)
	testifyRequire.Nil(t, senderEphemeralKeySignatureErr)
	// Set the EphemeralKeySignature to the signature obtained from the IdentitySign method
	chatMessageSender.EphemeralKeySignature = senderEphemeralKeySignature
	// Set the Message to the doube Ratchet message
	chatMessageSender.Message = &protobufDoubleRatchetMsgSender
	// Set the message receiver to message Receiver IdentityKey from his PreKeyBundle
	chatMessageSender.Receiver = []byte(receiverPreKeyBundlePublic.BundleIdentityKey)
	// Set the message sender to the message Sender IdentityKey
	chatMessageSender.Sender = []byte(identityPublicKeySenderHex)
	// Create a new message id
	messageID := uuid.NewV4()
	// Set the message ID
	chatMessageSender.MessageID = []byte(messageID.String())
	// Set the used shared secret, (not in plain form)
	chatMessageSender.UsedSharedSecret = []byte("@TODO")
	// Set the version
	// @TODO : setup proper versioning?
	chatMessageSender.Version = 1
	// Append the message to the slice of messages in our request

	// Change the message id so that it stores it as a unique message on the backend storage
	chatMessageSenderNewMessageID1 := chatMessageSender
	chatMessageSenderNewMessageID2 := chatMessageSender
	chatMessageSenderNewMessageID3 := chatMessageSender
	chatMessageSenderNewMessageID1.MessageID = []byte(uuid.NewV4().String())
	chatMessageSenderNewMessageID2.MessageID = []byte(uuid.NewV4().String())
	chatMessageSenderNewMessageID3.MessageID = []byte(uuid.NewV4().String())
	messageToBackendProto.Request.Messages = append(messageToBackendProto.Request.Messages, &chatMessageSenderNewMessageID1)
	messageToBackendProto.Request.Messages = append(messageToBackendProto.Request.Messages, &chatMessageSenderNewMessageID2)
	messageToBackendProto.Request.Messages = append(messageToBackendProto.Request.Messages, &chatMessageSenderNewMessageID3)
	// Marshal our protobuf ChatMessage structure so that we can send it via our websocket connection
	messageToBackendProtoBytes, messageToBackendProtoBytesErr := golangProto.Marshal(&messageToBackendProto)
	testifyRequire.Nil(t, messageToBackendProtoBytesErr)
	// Send our protobuf ChatMessage structure via our websocket connection
	writeMessageError := c.WebSocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToBackendProtoBytes)
	testifyRequire.Nil(t, writeMessageError)
	// For each message that we are sending to the backend
	_, messageFromBackendProtobufBytes, readMessageErr := c.WebSocketConnection.ReadMessage()
	testifyRequire.Nil(t, readMessageErr)
	protoUnmarshalErr := golangProto.Unmarshal(messageFromBackendProtobufBytes, &messageFromBackend)
	testifyRequire.Nil(t, protoUnmarshalErr)
	testifyRequire.Equal(t, "", messageFromBackend.Error)
	testifyRequire.Equal(t, messageFromBackend.RequestID, messageToBackendProto.RequestID)
} // func (c *Client) testSendMessage

func (c *Client) testRequestPreKeyBundle(t *testing.T, preKeyBundleIdentifier []byte) PreKeyBundlePublic {
	// Initialize our Message structure to send a request to the backend
	messageToBackendProto := backendProtobuf.BackendMessage{}
	// Set a request id
	messageToBackendProto.RequestID = uuid.NewV4().String()
	// Initialize an empty Request structure
	messageToBackendProto.Request = &backendProtobuf.BackendMessage_Request{}
	// Fill in the key of the client we want to requirest a pre key bundle for so that we can chat with
	messageToBackendProto.Request.PreKeyBundle = preKeyBundleIdentifier
	// Protobuf marshal our message structure so that we can send it over our websocket connection.
	messageToBackendProtoBytes, messageToBackendProtoErr := golangProto.Marshal(&messageToBackendProto)
	testifyRequire.Nil(t, messageToBackendProtoErr)
	// Send our pre key bundle request to the backend
	writeMessageErr := c.WebSocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToBackendProtoBytes)
	testifyRequire.Nil(t, writeMessageErr)
	// Read the response from the backend
	_, messageFromBackend, readMessageErr := c.WebSocketConnection.ReadMessage()
	testifyRequire.Nil(t, readMessageErr)
	// Create a structure that would hold the unmarshaled protobuf response from the backend
	var messageFromBackendProtobuf backendProtobuf.BackendMessage
	// Unmarshal the protobuf response from the backend
	protoUnmarshalErr := golangProto.Unmarshal(messageFromBackend, &messageFromBackendProtobuf)
	testifyRequire.Nil(t, protoUnmarshalErr)
	// Get the Response from the received message
	responseFromBackend := messageFromBackendProtobuf.Response
	testifyRequire.Equal(t, "", messageFromBackendProtobuf.Error)
	// Get the PreKeyBundle from the received response
	preKeyBundleFromBackend := responseFromBackend.PreKeyBundle
	// Get the OneTimePreKey from the received pre key bundle
	oneTimePreKeyFromBackend := preKeyBundleFromBackend.OneTimePreKey

	// Get the SignedPreKey from the received pre key bundle
	signedPreKeyFromBackend := preKeyBundleFromBackend.SignedPreKey
	// Get the Profile from the received pre key bundle
	profileFromBackend := preKeyBundleFromBackend.Profile
	// Get the identity public key corresponding to the received pre key bundle from the backend
	identityPublicKeyFromBackend := profileFromBackend.IdentityPubKey
	// Hex encode the identity public key corresponding to the received pre key bundle from the backend
	// Make sure that the hex encoded identity public key we used to make the initial request is the same as the one returned by the backend
	testifyRequire.Equal(t, preKeyBundleIdentifier, identityPublicKeyFromBackend)
	// Create a public pre key bundle structure
	requrestedPreKeyBundle := PreKeyBundlePublic{}
	// Set the pre key bundle IdentityKey
	requrestedPreKeyBundle.BundleIdentityKey = identityPublicKeyFromBackend
	// Set the pre key bundle ChatIdentityKey
	copy(requrestedPreKeyBundle.BundleChatIdentityKey[:], profileFromBackend.ChatIdentityPubKey[:])
	// Set the pre key bundle OneTimePreKey
	copy(requrestedPreKeyBundle.BundleOneTimePreKey[:], oneTimePreKeyFromBackend.Key)
	// Set the pre key bundle SignedPreKey
	copy(requrestedPreKeyBundle.BundleSignedPreKey[:], signedPreKeyFromBackend.Key)
	// Return a usable PreKeyBundle to be consumed by the client wishing to initiate a chat session
	return requrestedPreKeyBundle
} // testRequestPreKeyBundle(

func (c *Client) testReadDoubleRatchetMessages(t *testing.T, unreadChatMessage *backendProtobuf.ChatMessage, expectedDecryptedMessage string) {
	// Get the key manager for the receiver
	keyManagerReceiver := c.KeyManager
	// Get the message Receiver's chat id key pair
	chatIDKeyPairReceiver, chatIDKeyPairErr := keyManagerReceiver.ChatIdKeyPair()
	testifyRequire.Nil(t, chatIDKeyPairErr)
	// Create a new 25519 curve for message Receiver
	curveReceiver := bitnationX3dh.NewCurve25519(rand.Reader)
	// Create a new x3dh for the message Receiver using the 25519 curve and the message Receiver's chat id key pair
	x3dhReceiver := bitnationX3dh.New(&curveReceiver, sha256.New(), "testing", chatIDKeyPairReceiver)
	// Make it easy to get the signedPreKey private key associated with the signedPreKey public key
	signedPreKeyPairReceiverMap := make(map[[32]byte][32]byte)
	signedPreKeyPairReceiverMap[c.SignedPreKey.PublicKey] = c.SignedPreKey.PrivateKey
	// Make it easy to get the oneTimePreKey private key associated with the oneTimePreKey public key
	oneTimePreKeyPairReceiverMap := make(map[[32]byte][32]byte)
	// For each oneTimePreKey
	for _, oneTimePreKey := range c.OneTimePreKeys {
		// Associate the Public part with the Private part // This is all done locally on the client side
		oneTimePreKeyPairReceiverMap[oneTimePreKey.PublicKey] = oneTimePreKey.PrivateKey
	}
	// Conform to type requirements by creating a [32]byte variable for the OneTimePreKey
	unreadChatMessageOneTimePreKey32Byte := [32]byte{}
	// Conform to type requirements by creating a [32]byte variable for the SignedPreKey
	unreadChatMessageSignedPreKey32Byte := [32]byte{}
	// Copy the OneTimePreKey supplied in the protobuf chat message to the corresponding [32]byte OneTimePreKey variable
	copy(unreadChatMessageOneTimePreKey32Byte[:], unreadChatMessage.OneTimePreKey[:])
	// Copy the SignedPreKey supplied in the protobuf chat message to the corresponding [32]byte SignedPreKey variable
	copy(unreadChatMessageSignedPreKey32Byte[:], unreadChatMessage.SignedPreKey[:])
	// Get the private keys corresponding to the message Receiver's public keys
	receiverPreKeyBundlePrivate := PreKeyBundlePrivate{
		OneTimePreKey: oneTimePreKeyPairReceiverMap[unreadChatMessageOneTimePreKey32Byte],
		SignedPreKey:  signedPreKeyPairReceiverMap[unreadChatMessageSignedPreKey32Byte],
	}
	// Create a remoteChatIDKey variable to conform to the bitnationX3dh.PublicKey type requirement
	var remoteChatIDKey bitnationX3dh.PublicKey
	// Create a remoteEphemeralKey variable to conform to the bitnationX3dh.PublicKey type requirement
	var remoteEphemeralKey bitnationX3dh.PublicKey
	// Copy the bytes from the doubleRatchetMsgAlice.Header.DH to remoteChatIDKey
	copy(remoteChatIDKey[:], unreadChatMessage.Message.DoubleRatchetPK[:])
	// Copy the bytes from the EphemeralKey supplied in the protobuf chat message to remoteEphemeralKey
	copy(remoteEphemeralKey[:], unreadChatMessage.EphemeralKey[:])
	// Initialize an x3dh protocol using the ChatIDKey and EphemeralKey from the message Sender and the private OneTimePreKey and SignedPreKey parts from the message receiver
	customProtocolInitialization := bitnationX3dh.ProtocolInitialisation{
		RemoteIdKey:        remoteChatIDKey,
		RemoteEphemeralKey: remoteEphemeralKey,
		MyOneTimePreKey:    &receiverPreKeyBundlePrivate.OneTimePreKey,
		MySignedPreKey:     receiverPreKeyBundlePrivate.SignedPreKey,
	}
	// Derive the shared secret from the custom initialised x3dh protocol
	sharedSecretReceiver, sharedSecretErr := x3dhReceiver.SecretFromRemote(customProtocolInitialization)
	testifyRequire.Nil(t, sharedSecretErr)
	// Create a remoteChatIDKeyBytes variable to conform to the [32]byte type requirement and set it to the value of remoteChatIDKey
	var remoteChatIDKeyBytes [32]byte = remoteChatIDKey
	// Initiate a new double retchet session using the derived shared secret and the remoteChatIDKey
	var drSharedSec tiabcDoubleratchet.Key
	copy(drSharedSec[:], sharedSecretReceiver[:])
	doubleRatchetSessionReceiver, doubleRatchetSessionErr := tiabcDoubleratchet.NewWithRemoteKey(sharedSecretReceiver, remoteChatIDKeyBytes, tiabcDoubleratchet.WithKeysStorage(&tiabcDoubleratchet.KeysStorageInMemory{}))
	testifyRequire.Nil(t, doubleRatchetSessionErr)
	// Create a doubleRatchetKey variable to conform to the tiabcDoubleratchet.Key type requirement
	var doubleRatchetKey tiabcDoubleratchet.Key
	// Copy the bytes from remoteChatIDKey to the doubleRatchetKey
	copy(doubleRatchetKey[:], remoteChatIDKey[:])
	// Create a doubleRatchetHeader structure
	doubleRatchetHeader := tiabcDoubleratchet.MessageHeader{}
	// Set the sender's current ratchet public key
	doubleRatchetHeader.DH = doubleRatchetKey
	// Set the number of the message in the sending chain
	doubleRatchetHeader.N = unreadChatMessage.Message.N
	// Set the length of the previous sending chain.
	doubleRatchetHeader.PN = unreadChatMessage.Message.Pn
	// Create a doubleRatchetMessage structure
	doubleRatchetMessage := tiabcDoubleratchet.Message{}
	// Set the doubleRatchetMessage Header
	doubleRatchetMessage.Header = doubleRatchetHeader
	// Set the doubleRatchetMessage CipherText which is the encrypted double rateched message that we want to decrypt
	doubleRatchetMessage.Ciphertext = unreadChatMessage.Message.CipherText
	// Decrypt the doubleRatchetMessage using the previously initialized doubleRatchetSession from the message receiver
	decryptedMessageFromAlice, decryptedMessageFromAliceErr := doubleRatchetSessionReceiver.RatchetDecrypt(doubleRatchetMessage, []byte{})
	testifyRequire.Nil(t, decryptedMessageFromAliceErr)
	// Make sure that the decrypted message matches the original message
	testifyRequire.Equal(t, expectedDecryptedMessage, string(decryptedMessageFromAlice))

} // testReadDoubleRatchetMessages

func (c *Client) receiveUndeliveredMessages(t *testing.T) []*backendProtobuf.ChatMessage {
	// Read the message from backend
	_, undeliveredMessages, readMessageErr := c.WebSocketConnection.ReadMessage()
	testifyRequire.Nil(t, readMessageErr)
	// Create an empty BackendMessage structure
	messageFromBackendProto := backendProtobuf.BackendMessage{}
	// Unmarshal the undeliveredMessagesd into our backend message structure
	protoUnmarshalErr := golangProto.Unmarshal(undeliveredMessages, &messageFromBackendProto)
	testifyRequire.Nil(t, protoUnmarshalErr)
	// Return the undelivered messages
	return messageFromBackendProto.Request.Messages
}

func (c *Client) testAuth(t *testing.T) {
	// Initialize our Message structure to process the message from backend
	messageFromBackend := backendProtobuf.BackendMessage{}
	// Initialize our Message structure to send a response to the backend
	messageToBackend := backendProtobuf.BackendMessage{}
	// Initialize an empty Response structure
	messageToBackend.Response = &backendProtobuf.BackendMessage_Response{}
	// Initialize an empty Auth structure
	messageToBackend.Response.Auth = &backendProtobuf.BackendMessage_Auth{}
	// Read the data from the server which should contain the byte sequence we need to sign
	_, messageFromBackendBytes, readMessageErr := c.WebSocketConnection.ReadMessage()
	testifyRequire.Nil(t, readMessageErr)
	// Unmarshal the data from the server into our Message structure
	protoUnmarshalErr := golangProto.Unmarshal(messageFromBackendBytes, &messageFromBackend)
	testifyRequire.Nil(t, protoUnmarshalErr)
	// Set the id of request we are replying to
	messageToBackend.RequestID = messageFromBackend.RequestID
	// Create a byte slice to store our random bytes
	clientRandomBytes := make([]byte, 4)
	// Read random bytes into our slice
	_, randomBytesErr := rand.Read(clientRandomBytes)
	testifyRequire.Nil(t, randomBytesErr)
	// Get the byte sequence that we need to sign
	byteSequenceToSign := messageFromBackend.Request.Auth.ToSign
	// Make sure that backend sends us exactly 4 bytes to avoid signing something potentially malicious
	testifyRequire.Equal(t, 4, len(byteSequenceToSign))
	// Append our own 4 random bytes to prevent backend abuse
	byteSequenceToSign = append(byteSequenceToSign, clientRandomBytes...)
	// Make sure that we are about to sign exactly 8 bytes
	testifyRequire.Equal(t, 8, len(byteSequenceToSign))
	// Create a new keyStore for Client using the created mnemnonic
	keyStoreClient, keystoreClientErr := panthalassaKeyStore.NewFromMnemonic(c.Mnemonic)
	testifyRequire.Nil(t, keystoreClientErr)
	// Create a new keyManager for Client using the created key store
	keyManagerClient := panthalassaKeyManager.CreateFromKeyStore(keyStoreClient)
	// Sign the byte sequence given by the server using Client's key manager
	signedByteSequence, signedByteSequenceErr := keyManagerClient.IdentitySign(byteSequenceToSign)
	testifyRequire.Nil(t, signedByteSequenceErr)
	// Get Client's hex encoded identity public key
	identityPublicKeyClientHex, identityPublicKeyClientHexErr := keyManagerClient.IdentityPublicKey()
	testifyRequire.Nil(t, identityPublicKeyClientHexErr)
	// Decode Client's hex encoded identity public key as bytes
	identityPublicKeyClientBytes, identityPublicKeyClientErr := hex.DecodeString(identityPublicKeyClientHex)
	testifyRequire.Nil(t, identityPublicKeyClientErr)
	// Set the bytes prespresentation of Client's hex encoded identity public key in our protobuf Auth structure so we can send it to the server
	messageToBackend.Response.Auth.IdentityPublicKey = identityPublicKeyClientBytes
	// Set Client's 8 byte sequence which was signed in our protobuf Auth structure so we can send it to the server
	messageToBackend.Response.Auth.ToSign = byteSequenceToSign
	// Set Client's signed byte sequence as a signature in our protobuf Auth structure so we can send it to the server
	messageToBackend.Response.Auth.Signature = signedByteSequence
	// Marshal our protobuf Auth structure so that we can send it via our websocket connection
	messageToBackendBytes, protobufAuthBytesErr := golangProto.Marshal(&messageToBackend)
	testifyRequire.Nil(t, protobufAuthBytesErr)
	// Send our protobuf Auth structure via our websocket connection
	writeMessageErr := c.WebSocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToBackendBytes)
	testifyRequire.Nil(t, writeMessageErr)
	// Read back the response from the backend
	_, messageFromBackendBytes, readMessageErr = c.WebSocketConnection.ReadMessage()
	testifyRequire.Nil(t, readMessageErr)
	// Make sure the backend sends us back the .RequestID as a means to confirm that it's successful
	protoUnmarshalErr = golangProto.Unmarshal(messageFromBackendBytes, &messageFromBackend)
	testifyRequire.Nil(t, protoUnmarshalErr)
	testifyRequire.Equal(t, "", messageFromBackend.Error)
	testifyRequire.Equal(t, messageToBackend.RequestID, messageFromBackend.RequestID)

}

var Reader io.Reader

// Satisfy interface requirements
func Read(b []byte) (n int, err error) {
	return io.ReadFull(Reader, b)
}

// Create doubleratchetKeyPair struct needed to start a custom doubleratchet session
type doubleratchetKeyPair struct {
	keyPair bitnationX3dh.KeyPair
}

// Add PrivateKey method to conform to tiabcDoubleratchet.DHPair interface requrements
func (d doubleratchetKeyPair) PrivateKey() tiabcDoubleratchet.Key {
	var byt [32]byte = d.keyPair.PrivateKey
	return byt
}

// Add PublicKey method to conform to tiabcDoubleratchet.DHPair interface requrements
func (d doubleratchetKeyPair) PublicKey() tiabcDoubleratchet.Key {
	var byt [32]byte = d.keyPair.PublicKey
	return byt
}

type PreKeyBundlePublic struct {
	BundleChatIdentityKey bitnationX3dh.PublicKey
	BundleSignedPreKey    bitnationX3dh.PublicKey
	BundleOneTimePreKey   bitnationX3dh.PublicKey
	BundleIdentityKey     []byte
	BundleSignature       [64]byte
}

type PreKeyBundlePrivate struct {
	OneTimePreKey bitnationX3dh.PrivateKey
	SignedPreKey  bitnationX3dh.PrivateKey
}

func (b *PreKeyBundlePublic) IdentityKey() bitnationX3dh.PublicKey {
	return b.BundleChatIdentityKey
}

func (b *PreKeyBundlePublic) SignedPreKey() bitnationX3dh.PublicKey {
	return b.BundleSignedPreKey
}

func (b *PreKeyBundlePublic) OneTimePreKey() *bitnationX3dh.PublicKey {
	return &b.BundleOneTimePreKey
}

func (b *PreKeyBundlePublic) ValidSignature() (bool, error) {
	// @TODO REMOVE RETURN TRUE AND CALCULATE SIGNATURE IN ANOTHER WAY
	return true, nil
	return cryptoEd25519.Verify(b.BundleIdentityKey[:], b.hashBundle(), b.BundleSignature[:]), nil
}

// sign profile with given private key
func (b *PreKeyBundlePublic) Sign(km panthalassaKeyManager.KeyManager) error {
	signature, err := km.IdentitySign(b.hashBundle())
	copy(b.BundleSignature[:], signature[:])
	return err

}

func (b *PreKeyBundlePublic) hashBundle() []byte {
	// concat profile information
	c := append(b.BundleChatIdentityKey[:], b.BundleSignedPreKey[:]...)
	c = append(c, b.BundleOneTimePreKey[:]...)
	c = append(c, b.BundleIdentityKey...)
	return sha256.New().Sum(c)

}

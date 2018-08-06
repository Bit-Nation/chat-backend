package chatbackend

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"

	profile "github.com/Bit-Nation/panthalassa/profile"
	backendProtobuf "github.com/Bit-Nation/protobuffers"
	golangProto "github.com/golang/protobuf/proto"
	gorillaMux "github.com/gorilla/mux"
	gorillaWebSocket "github.com/gorilla/websocket"
	cryptoEd25519 "golang.org/x/crypto/ed25519"
)

var papertrailURL = os.Getenv("PAPERTRAIL")

// StartWebSocketServer starts the websocket server
func StartWebSocketServer() {
	// Create new gorillaRouter
	gorillaRouter := gorillaMux.NewRouter()
	// Bind an endpoint path to handleWebSocketConnection
	gorillaRouter.HandleFunc("/chat", HandleWebSocketConnection)
	gorillaRouter.HandleFunc("/profile", HandleProfile)
	// Listen on a specific port for incoming connections
	if listenAndServeErr := http.ListenAndServe(":8080", gorillaRouter); listenAndServeErr != nil {
		// If there is an error while setting up, panic and show us the error
		logError(syslog.LOG_CRIT, listenAndServeErr)
	} // if listenAndServeErr
} // func startWebSocketServer

// HandleProfile decides what happens when a client requests or uploads a profile
func HandleProfile(serverHTTPResponse http.ResponseWriter, clientHTTPRequest *http.Request) {
	// Make sure the client passes the bearer authentication
	if clientHTTPRequest.Header.Get("Bearer") != "5d41402abc4b2a76b9719d911017c592" {
		http.Error(serverHTTPResponse, "Forbidden", 403)
		return
	} // if clientHTTPRequest.Header.Get("Bearer")
	// Choose different actions depending on the type of request
	switch clientHTTPRequest.Method {
	case "GET":
		// Get the identity public key for the client that we want to obtain the profile for
		profile, profileErr := getProfileFromStorage(clientHTTPRequest.Header.Get("Identity"))
		// If there is an error while obtaining the profile, inform the client
		if profileErr != nil {
			http.Error(serverHTTPResponse, profileErr.Error(), 500)
			return
		} // if profileErr != nil {
		// Write the protobyfBytes of the Profile protobuf structure to the client, in case of ann error inform the client
		if _, serverHTTPResponseErr := serverHTTPResponse.Write(profile); serverHTTPResponseErr != nil {
			logError(syslog.LOG_ERR, serverHTTPResponseErr)
			http.Error(serverHTTPResponse, serverHTTPResponseErr.Error(), 500)
			return
		} // if _, serverHTTPResponseErr
	case "PUT":
		var profileProtobuf backendProtobuf.Profile
		// Read a base64 representation of the Profile protobuf structure bytes
		profileBase64Bytes, readErr := ioutil.ReadAll(clientHTTPRequest.Body)
		if readErr != nil {
			http.Error(serverHTTPResponse, readErr.Error(), 500)
			return
		} // if readErr != nil {
		// Create a string representation of the profileBase64Bytes for easier usage and decoding
		profileBase64String := string(profileBase64Bytes)
		// Decode the string representation of the profileBase64Bytes into protobuf bytes
		profileProtobufBytes, profileBytesErr := base64.StdEncoding.DecodeString(profileBase64String)
		if profileBytesErr != nil {
			http.Error(serverHTTPResponse, readErr.Error(), 500)
			return
		} // if profileBytesErr != nil
		// Unmarshal the protobuf bytes into protobuf Profile structure
		if protoUnmarshalErr := golangProto.Unmarshal(profileProtobufBytes, &profileProtobuf); protoUnmarshalErr != nil {
			http.Error(serverHTTPResponse, protoUnmarshalErr.Error(), 500)
			return
		} // if protoUnmarshalErr
		// Create a profile object from our protobuf Profile structure
		profileObject, profileErr := profile.ProtobufToProfile(&profileProtobuf)
		if profileErr != nil {
			http.Error(serverHTTPResponse, profileErr.Error(), 500)
			return
		}
		// Validate the signature of the profile, return if there is an error as we don't accept profiles with invalid signatures
		validProfileSignature, validProfileSignatureErr := profileObject.SignaturesValid()
		if validProfileSignatureErr != nil {
			http.Error(serverHTTPResponse, validProfileSignatureErr.Error(), 500)
			return
		}
		// Double check that the SignaturesValid() method returned true
		if !validProfileSignature {
			http.Error(serverHTTPResponse, errors.New("Invalid Signature").Error(), 500)
			return
		}
		// Persist the base64 representation of the Profile protobuf structure bytes, in case of an error inform the client, othterwise inform that it's ok
		if persistProfileToStorageErr := persistProfileToStorage(clientHTTPRequest.Header.Get("Identity"), profileBase64String); persistProfileToStorageErr != nil {
			http.Error(serverHTTPResponse, persistProfileToStorageErr.Error(), 500)
		} else {
			// Inform the client that everything is ok
			serverHTTPResponse.WriteHeader(http.StatusOK)
		} // else
	// Forbid other methods at the time being
	default:
		http.Error(serverHTTPResponse, "Method Not Allowed", 405)
	} // switch clientHTTPRequest.Method
} // func HandleProfile

// HandleWebSocketConnection decides what happens when a client establishes a websocket connection to the server
func HandleWebSocketConnection(serverHTTPResponse http.ResponseWriter, clientHTTPRequest *http.Request) {
	// Allow only requests which contain the specific Bearer header
	// Allow only GET requests
	if clientHTTPRequest.Header.Get("Bearer") != "5d41402abc4b2a76b9719d911017c592" || clientHTTPRequest.Method != "GET" {
		// If a client is missing the Bearer header or is using a different method than GET return a Forbidden error
		http.Error(serverHTTPResponse, "Forbidden", 403)
		return
	}
	// Prepare to upgrade the HTTP connection to a WebSocket connection
	httpConnectionUpgrader := gorillaWebSocket.Upgrader{}
	// Upgrade the HTTP connection to a WebSocket connection
	websocketConnection, websocketConnectionErr := httpConnectionUpgrader.Upgrade(serverHTTPResponse, clientHTTPRequest, nil)
	if websocketConnectionErr != nil {
		// If there was an error while upgrading the HTTP connection to a WebSocket connection return a relevant error
		http.Error(serverHTTPResponse, "Unable to upgrade HTTP connection to a WebSocket connection", 400)
		// Close the websocket connection
		websocketConnection.Close()
		return
	}
	// Initialise the authenticatedClientFirestore object
	authenticatedClient := authenticatedClientFirestore{}
	// Set the websocketConnection so that we can send an error back to the client in case auth fails
	authenticatedClient.websocketConnection = websocketConnection
	// Require successful authentication before allowing a client to send a message
	authenticatedIdentityPublicKeyClient, websocketConnectionRequestAuthErr := requestAuth(websocketConnection)
	// If the authentication failed,
	if websocketConnectionRequestAuthErr != nil {
		// Log a failed authentication attempt
		logError(syslog.LOG_ERR, websocketConnectionRequestAuthErr)
		// In case there was a protobuf marshal error, The client would receive an empty []byte and should handle it as an invalid response
		// Even with an invalid response, the client should still take the hint that his authentication attempt has failed
		if writeMessageErr := authenticatedClient.sendErrorToClient(); writeMessageErr != nil {
			logError(syslog.LOG_ERR, writeMessageErr)
		} // if writeMessageErr
		logError(syslog.LOG_INFO, errors.New("terminating websocket connection to client"))
		// Close the websocket connection
		websocketConnection.Close()
		return
	} // if websocketConnectionRequestAuthErr != nil
	// Only set the authenticatedIdentityPublicKeyHex once authentication has been successful
	authenticatedClient.authenticatedIdentityPublicKeyHex = hex.EncodeToString(authenticatedIdentityPublicKeyClient)
	// Continue in the scope of the authenticatedWebsocketConnection to allow for easier testing
	authenticatedWebsocketConnection(&authenticatedClient)
} // func handleWebSocketConnection

func authenticatedWebsocketConnection(storage storageInterface) {
	authenticatedClient, authenticatedClientErr := storage.getClientDataFromStorage()
	if authenticatedClientErr != nil {
		logError(syslog.LOG_ERR, authenticatedClientErr)
	} // if authenticatedClientErr != nil
	if len(authenticatedClient.messagesToBeDelivered) > 0 {
		// If there are no errors while deliveing the messages to the client
		if deliverMessagesErr := authenticatedClient.deliverMessages(authenticatedClient.messagesToBeDelivered); deliverMessagesErr == nil {
			authenticatedClient.deleteFieldFromStorage("chatMessages", "")
		} // if deliverMessagesErr == nil
	} // if len(messagesToBeDelivered > 0)

	// Try to process a message from the client
	websocketConnectionProcessMessageErr := authenticatedClient.processMessage()
	// For as long as we don't enounter an error while processing messages from the client
	for websocketConnectionProcessMessageErr == nil {
		// Process messages from the client
		websocketConnectionProcessMessageErr = authenticatedClient.processMessage()
	} // for websocketConnectionProcessMessageErr == nil
	// Once we enounter an error while processing messages from the client
	// Log the error we encountered
	logError(syslog.LOG_ERR, websocketConnectionProcessMessageErr)
	// If there is an error while sending the error to the client, log the error
	if writeMessageErr := authenticatedClient.sendErrorToClient(); writeMessageErr != nil {
		logError(syslog.LOG_ERR, writeMessageErr)
	} // if writeMessageErr
	logError(syslog.LOG_INFO, errors.New("terminating websocket connection to client"))
	// Close the websocket connection
	authenticatedClient.websocketConnection.Close()
	return
	// Read first message from client
} // func authenticatedWebsocketConnection

func (a *authenticatedClientFirestore) sendErrorToClient() error {
	// Create a protobuf message structure to send back to the client
	var messageToClientProtobuf backendProtobuf.BackendMessage
	// Create a []byte variable to hold the marshaled protobuf bytes
	var messageToClientProtobufBytes []byte
	// Create an error variable to hold an error in case the protobuf marshaling failed
	var messageToClientProtobufBytesErr error
	// Set the authentication error in the message structure so it can be sent back to the client
	if a.encounteredError != nil {
		messageToClientProtobuf.Error = a.encounteredError.Error()
	} // if a.encounteredError != nil
	// If there is an error while marshaling the message structure, log the error and continue with the rest of the function
	if messageToClientProtobufBytes, messageToClientProtobufBytesErr = golangProto.Marshal(&messageToClientProtobuf); messageToClientProtobufBytesErr != nil {
		logError(syslog.LOG_ERR, messageToClientProtobufBytesErr)
	} // if messageToClientProtobufBytes
	// Returned the marshaled message bytes
	if writeMessageErr := a.websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientProtobufBytes); writeMessageErr != nil {
		return writeMessageErr
	} // if writeMessageErr
	// Return nil when no error was encountered
	return nil
} // func sendErrorToClient

func (a *authenticatedClientFirestore) processMessage() error {
	// Initialize an empty variable to hold the protobuf message
	var messageFromClientProtobuf backendProtobuf.BackendMessage
	// Read a message from a client over the websocket connection
	_, messageFromClientBytes, readMessageErr := a.websocketConnection.ReadMessage()
	// If there is an error while reading the message from client
	if readMessageErr != nil {
		// If it's not a normal connection closure, return an error
		if !gorillaWebSocket.IsCloseError(readMessageErr, gorillaWebSocket.CloseNormalClosure) {
			return readMessageErr
		}
		return nil
	}
	// Unmarshal the protobuf bytes from the message we received into our protobuf message structure
	if protoUnmarshalErr := golangProto.Unmarshal(messageFromClientBytes, &messageFromClientProtobuf); protoUnmarshalErr != nil {
		return protoUnmarshalErr
	}
	// Outer master switch, cases are valid if they are true
	switch {
	// In case a message has both a request and a response
	case messageFromClientProtobuf.Request != nil && messageFromClientProtobuf.Response != nil:
		// Return an error as it's not allowed for a message to have both a response and a request at the same time
		return errors.New("A message can’t have a response and a request at the same time")
	// If the message is a request
	case messageFromClientProtobuf.Request != nil:
		// In case a requestID is missing from a client request
		if messageFromClientProtobuf.RequestID == "" {
			return errors.New("A valid client request should always have a RequestID")
		} // if messageFromClientProtobuf.RequestID
		// Inner switch in case we have a Request from client, cases are valid if they are true
		switch {
		case messageFromClientProtobuf.Request.Messages != nil:
			persistChatMessagesFromClientErr := a.persistChatMessagesFromClient(messageFromClientProtobuf.Request.Messages)
			return persistChatMessagesFromClientErr
		// @TODO wait for @Gross input on message states
		case messageFromClientProtobuf.Request.MessageStateChange != nil:
			fmt.Println(messageFromClientProtobuf.Request.MessageStateChange, "MessageStateChange")
		case messageFromClientProtobuf.Request.NewOneTimePreKeys != 0:
			return errors.New("Only backend is allowed to request NewOneTimePreKeys")
		case messageFromClientProtobuf.Request.PreKeyBundle != nil:
			usedOneTimePreKey, deliverRequestedPreKeyBundleErr := a.deliverRequestedPreKeyBundle(messageFromClientProtobuf.Request.PreKeyBundle)
			if deliverRequestedPreKeyBundleErr == nil {
				a.deleteFieldFromStorage("oneTimePreKeys", usedOneTimePreKey)
			} // if deliverRequestedPreKeyBundleErr
			return deliverRequestedPreKeyBundleErr
		case messageFromClientProtobuf.Request.Auth != nil:
			return errors.New("Backend should request authentication, not the client")
		} // Inner switch {
	// If the message is a response
	case messageFromClientProtobuf.Response != nil:
		// Inner switch in case we have a Response from client, cases are valid if they are true
		switch {
		case messageFromClientProtobuf.Response.Auth != nil:
			return errors.New("Authentication should not be handled here")
		case messageFromClientProtobuf.Response.OneTimePrekeys != nil:
			return a.persistOneTimePreKeysFromClient(messageFromClientProtobuf.Response.OneTimePrekeys)
		case messageFromClientProtobuf.Response.PreKeyBundle != nil:
			return errors.New("Only backend is allowed to provide a PreKeyBundle")
		case messageFromClientProtobuf.Response.SignedPreKey != nil:
			return a.persistSignedPreKeyFromClient(messageFromClientProtobuf.Response.SignedPreKey)
		} // Inner switch in case we have a Response from client

	// The only time it should reach the default case is when both messageFromClientProtobuf.Request == nil && messageFromClientProtobuf.Response == nil
	default:
		if messageFromClientProtobuf.Error != "" {
			return errors.New(messageFromClientProtobuf.Error)
		}

		if messageFromClientProtobuf.RequestID != "" {
			// @TODO RESPOND TO THIS REQUEST
		}

		if messageFromClientProtobuf.RequestID == "" {
			a.websocketConnection.Close()
		}
	}
	return nil
} // func processMessage

func (a *authenticatedClientFirestore) deliverRequestedPreKeyBundle(requestedPreKeyBundle []byte) (string, error) {
	// Store a temporary snapshot of the original authenticatedClientFirestore
	originalClient := *a
	// Set the authenticatedIdentityPublicKeyHex to the identityPublicKeyHex of the client that we should obtain a preKeyBundle for
	a.authenticatedIdentityPublicKeyHex = hex.EncodeToString(requestedPreKeyBundle)
	// Get the data from storage related to the identityPublicKeyHex of the client that we should obtain a preKeyBundle for
	a.getClientDataFromStorage()
	// Initialize an empty variable to hold the marshaled protobuf bytes of our response to the client
	var messageToClientProtobufBytes []byte
	// Initialize an empty variable to hold a protobuf error in case there is one
	var messageToClientProtobufErr error
	// Initialize an empty variable to hold the protobuf message
	var messageToClientProtobuf backendProtobuf.BackendMessage
	// Initialize an empty Response structure which would hold our response to the client
	messageToClientProtobuf.Response = &backendProtobuf.BackendMessage_Response{}
	// Initialize an empty PreKeyBundle structure which would hold the requested PreKeyBundle if it exists
	messageToClientProtobuf.Response.PreKeyBundle = &backendProtobuf.BackendMessage_PreKeyBundle{}
	// Initialize an empty Profile structure which would hold the requested Profile if it exists
	messageToClientProtobuf.Response.PreKeyBundle.Profile = &backendProtobuf.Profile{}
	// Initialize an empty PreKey structure which would hold the requested SignedPreKey if it exists
	messageToClientProtobuf.Response.PreKeyBundle.SignedPreKey = &backendProtobuf.PreKey{}
	// Initialize an empty PreKey structure which would hold the requested OneTimePreKey if it exists
	messageToClientProtobuf.Response.PreKeyBundle.OneTimePreKey = &backendProtobuf.PreKey{}
	// If there is an error with the unmarshalling, fill in the error field in the message to client with the error that occured
	if protoUnmarshalErr := golangProto.Unmarshal(a.profile, messageToClientProtobuf.Response.PreKeyBundle.Profile); protoUnmarshalErr != nil {
		return "", protoUnmarshalErr
	} // if protoUnmarshalErr
	// If there is an error with the unmarshalling, fill in the error field in the message to client with the error that occured
	if protoUnmarshalErr := golangProto.Unmarshal(a.signedPreKey, messageToClientProtobuf.Response.PreKeyBundle.SignedPreKey); protoUnmarshalErr != nil {
		return "", protoUnmarshalErr
	} // if protoUnmarshalErr != nil
	// Use a single oneTimePreKey
	for _, oneTimePreKey := range a.oneTimePreKeys {
		// If there is an error with the unmarshalling, fill in the error field in the message to client with the error that occured
		if protoUnmarshalErr := golangProto.Unmarshal(oneTimePreKey, messageToClientProtobuf.Response.PreKeyBundle.OneTimePreKey); protoUnmarshalErr != nil {
			return "", protoUnmarshalErr
		} // if protoUnmarshalErr != nil
		// break after using a single oneTimePreKey
		break
	} // for _, oneTimePreKey := range a.oneTimePreKeys {
	// Use protobufs to marshal our message structure so that we can send it over the websocket connection
	messageToClientProtobufBytes, messageToClientProtobufErr = golangProto.Marshal(&messageToClientProtobuf)
	// If there is an error while trying to perform protobuf marshaling
	if messageToClientProtobufErr != nil {
		// Initialise an empty message structure with the hopes that it will marshal correctly if it's empty
		messageToClientProtobuf = backendProtobuf.BackendMessage{}
		// Fill in the error field in the message to client with the error that occured
		messageToClientProtobuf.Error = messageToClientProtobufErr.Error()
		// Attempt to marshal the message structure again so that we can send it over the websocket connection
		messageToClientProtobufBytes, messageToClientProtobufErr = golangProto.Marshal(&messageToClientProtobuf)
	} // if protobufMessageToClientErr != nil {
	// Send our message over the websocket connection
	// Restore the temporary snapshot of the original authenticatedClientFirestore
	a = &originalClient
	usedOneTimePreKey := fmt.Sprint(messageToClientProtobuf.Response.PreKeyBundle.OneTimePreKey.TimeStamp)
	return usedOneTimePreKey, a.websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientProtobufBytes)
}

func (a authenticatedClientFirestore) deliverMessages(messagesToBeDelivered [][]byte) error {
	// Initialize an empty variable to hold the marshaled protobuf bytes
	var messageToClientProtobufBytes []byte
	// Initialize an empty variable to hold a protobuf error in case there is one
	var messageToClientProtobufErr error
	// Initialize an empty variable to hold the protobuf message
	var messageToClientProtobuf backendProtobuf.BackendMessage
	// Initialize the Request portion of the message
	messageToClientProtobuf.Request = &backendProtobuf.BackendMessage_Request{}
	// Initialize the ChatMessage portion of the Request
	messageToClientProtobuf.Request.Messages = []*backendProtobuf.ChatMessage{}
	// Iterate over all of the pending messages
	for _, singleMessageToBeDelivered := range messagesToBeDelivered {
		// Initialize a ChatMessage protobuf to hold a single message which will be appended to the []*backendProtobuf.ChatMessage{} slice
		singleMessageToBeDeliveredProtobuf := backendProtobuf.ChatMessage{}
		// Unmarshal the singleMessageToBeDelivered to the singleMessageToBeDeliveredProtobuf structure
		if protoUnmarshalErr := golangProto.Unmarshal(singleMessageToBeDelivered, &singleMessageToBeDeliveredProtobuf); protoUnmarshalErr != nil {
			return protoUnmarshalErr
		} // if protoUnmarshalErr
		// Append the message  to the []*backendProtobuf.ChatMessage{} slice
		messageToClientProtobuf.Request.Messages = append(messageToClientProtobuf.Request.Messages, &singleMessageToBeDeliveredProtobuf)
	} // for _, singleMessageToBeDelivered := range messagesToBeDelivered
	// Marshal the protobuf message structure so that it can be sent to the client over the websocket connection
	messageToClientProtobufBytes, messageToClientProtobufErr = golangProto.Marshal(&messageToClientProtobuf)
	// If we encounter an error while marshaling the protobuf message structure
	if messageToClientProtobufErr != nil {
		return messageToClientProtobufErr
	}
	// Send the mashalled protobuf message structure over the websocket connection
	if writeMessageErr := a.websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientProtobufBytes); writeMessageErr != nil {
		return writeMessageErr
	} // if writeMessageErr
	return nil
} // func deliverMessages

func requestAuth(websocketConnection *gorillaWebSocket.Conn) ([]byte, error) {
	// Initialize an empty Message structure
	messageFromClient := backendProtobuf.BackendMessage{}
	// Initialize an empty Response structure
	messageFromClient.Response = &backendProtobuf.BackendMessage_Response{}
	// Initialize an empty Message structure
	messageToClient := backendProtobuf.BackendMessage{}
	// Initialize an empty Request structure
	messageToClient.Request = &backendProtobuf.BackendMessage_Request{}
	// Initialize an empty Auth structure
	messageToClient.Request.Auth = &backendProtobuf.BackendMessage_Auth{}
	// Create a byte slice to store our random bytes
	backendRandomBytes := make([]byte, 4)
	// Read random bytes into our slice, in case of an error, return it
	if _, randomBytesErr := rand.Read(backendRandomBytes); randomBytesErr != nil {
		return nil, randomBytesErr
	} // if randomBytesErr != nil
	// Set the byte sequence that the client needs to sign
	messageToClient.Request.Auth.ToSign = backendRandomBytes
	// Prepare the data to be sent to the client
	messageToClientBytes, messageToClientBytesErr := golangProto.Marshal(&messageToClient)
	// If there is an error while trying to perform protobuf marshaling, terminate the connection
	if messageToClientBytesErr != nil {
		return nil, messageToClientBytesErr
	} // if messageToClientBytesErr != nil
	// Send the protobuf data to the client containing the sequence of bytes he needs to sign
	websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientBytes)
	// Read the response from the client which should contain his IdenetityPublicKey and the signed byte sequence
	_, messageFromClientProto, readMessageErr := websocketConnection.ReadMessage()
	// In case of an error, terminate the connection
	if readMessageErr != nil {
		return nil, readMessageErr
	}
	// Unmarshal the response from the client into our protobuf Auth structure, and in case of an error, terminate the connection
	if protoUnmarshalErr := golangProto.Unmarshal(messageFromClientProto, &messageFromClient); protoUnmarshalErr != nil {
		return nil, protoUnmarshalErr
	} // if protoUnmarshalErr
	// Create a [32]byte{} identityPublicKey to satisfy cryptoEd25519.Verify() type requirements
	identityPublicKey := [32]byte{}
	// Create a [64]byte{} byteSequenceToSignSignature to satisfy cryptoEd25519.Verify() type requirements
	byteSequenceToSignSignature := [64]byte{}
	// Create a string representation of the Identity Public Key
	identityPublicKeyBytes := messageFromClient.Response.Auth.IdentityPublicKey
	// Decode the hex representation of the identityPublicKey here as transmitting it over the network without hex encoding can cause issues with some clients
	// Get the byte sequence which was signed by the client
	byteSequenceThatClientSigned := messageFromClient.Response.Auth.ToSign
	if len(byteSequenceThatClientSigned) != 8 {
		return nil, errors.New("Signed byte sequence should be exactly 8 bytes")
	} // if len(byteSequenceThatClientSigned) != 8
	// Check if the byte sequence that was signed by the client contains the initial bytes we sent to the client
	if !bytes.HasPrefix(byteSequenceThatClientSigned, backendRandomBytes) {
		// If the client has modified the bytes we sent, return an error pointing out that this behavior is not allowed
		return nil, errors.New("Client is only allowed to append a byte sequence, and not to modify the one which was sent")
	}
	// Make sure that the identityPublicKey is exactly 32 bytes
	if len(identityPublicKeyBytes) != 32 {
		return nil, errors.New("identityPublicKey should be exactly 32 bytes")
	} // if len(identityPublicKey) != 32
	// Fill the newly created identityPublicKey with the hex decoded representation of the IdentityPublicKey contained in the response from the client
	copy(identityPublicKey[:], identityPublicKeyBytes)
	// Make sure that the Signature is exactly 64 bytes
	if len(messageFromClient.Response.Auth.Signature) != 64 {
		return nil, errors.New("Signature should be exactly 64 bytes")
	} // if len(messageFromClient.Response.Auth.Signature) != 32
	// Fill the newly created byteSequenceToSignSignature with the Signature contained in the response from the client
	copy(byteSequenceToSignSignature[:], messageFromClient.Response.Auth.Signature)
	// Verify the validity of the signature using cryptoEd25519.Verify()
	if cryptoEd25519.Verify(identityPublicKey[:], byteSequenceThatClientSigned, byteSequenceToSignSignature[:]) {
		// If the signed byte sequence from client has a valid signature, echo the authentication attempt back to the client so that he knows it was successful
		if writeMessageError := websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageFromClientProto); writeMessageError != nil {
			return nil, writeMessageError
		} // if writeMessageError
		// Return the identityPublicKey of the authenticated client
		return identityPublicKeyBytes, nil
	} // if cryptoEd25519.Verify
	// If cryptoEd25519.Verify() failed to verify the signature, return a matching reponse
	return nil, errors.New("Invalid Signature")
} // func requestAuth

func logError(priority syslog.Priority, err error) {
	// If the environment variable for the papertrail url is not set
	if papertrailURL == "" {
		// Use default logging
		logDefault(priority, err)
		return
	} // if papertrailURL == ""
	// Establish connection to the remote papertrail url
	papertrail, papertrailErr := syslog.Dial("udp", papertrailURL, syslog.LOG_EMERG|syslog.LOG_KERN, "panthalassa-chat-backend")
	// if there is an error, log the error normally and return
	if papertrailErr != nil {
		logDefault(syslog.LOG_EMERG, papertrailErr)
		return
	}
	// Use different logging functions depending on the error priority
	switch priority {
	case syslog.LOG_EMERG:
		papertrail.Emerg(err.Error())
	case syslog.LOG_ALERT:
		papertrail.Alert(err.Error())
	case syslog.LOG_CRIT:
		papertrail.Crit(err.Error())
	case syslog.LOG_ERR:
		papertrail.Err(err.Error())
	case syslog.LOG_WARNING:
		papertrail.Warning(err.Error())
	case syslog.LOG_NOTICE:
		papertrail.Notice(err.Error())
	case syslog.LOG_INFO:
		papertrail.Info(err.Error())
	case syslog.LOG_DEBUG:
		papertrail.Debug(err.Error())
	default:
		papertrail.Err(err.Error())
	} // switch priority {
} // func logError

func logDefault(priority syslog.Priority, err error) {
	// Use default logging
	log.Println(priority, err)
}

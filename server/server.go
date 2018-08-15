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
	"strconv"

	uuid "github.com/satori/go.uuid"
	profile "github.com/Bit-Nation/panthalassa/profile"
	backendProtobuf "github.com/Bit-Nation/protobuffers"
	golangProto "github.com/golang/protobuf/proto"
	gorillaMux "github.com/gorilla/mux"
	gorillaWebSocket "github.com/gorilla/websocket"
	cryptoEd25519 "golang.org/x/crypto/ed25519"
)

var papertrailURL = os.Getenv("PAPERTRAIL")
var production = os.Getenv("PRODUCTION")
var authenticatedClientWebSocketConnectionMap = make(map[string]*gorillaWebSocket.Conn)

// StartWebSocketServer starts the websocket server
func StartWebSocketServer() {

	// Get the port on which the chat backend should be listening on
	listenPort := os.Getenv("PORT")
	// Create new gorillaRouter
	gorillaRouter := gorillaMux.NewRouter()
	// Bind an endpoint path to handleWebSocketConnection
	gorillaRouter.HandleFunc("/chat", HandleWebSocketConnection)
	gorillaRouter.HandleFunc("/profile", HandleProfile)

	// Listen on a specific port for incoming connections
	if listenAndServeErr := http.ListenAndServe(":"+listenPort, gorillaRouter); listenAndServeErr != nil {
		// If there is an error while setting up, panic and show us the error
		logError(syslog.LOG_CRIT, listenAndServeErr)
	} // if listenAndServeErr
} // func startWebSocketServer

// HandleProfile decides what happens when a client requests or uploads a profile
func HandleProfile(serverHTTPResponse http.ResponseWriter, clientHTTPRequest *http.Request) {
	// Get bearer token from environment variable
	bearerToken := os.Getenv("BEARER")
	// Make sure the client passes the bearer authentication
	if clientHTTPRequest.Header.Get("Bearer") != bearerToken {
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
		if _, serverHTTPResponseErr := serverHTTPResponse.Write([]byte(base64.StdEncoding.EncodeToString(profile))); serverHTTPResponseErr != nil {
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
		if persistProfileToStorageErr := persistProfileToStorage(hex.EncodeToString(profileObject.Information.IdentityPubKey), profileBase64String); persistProfileToStorageErr != nil {
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
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("Pre-bearer, client connected"))
	} // if production == ""
	// Get bearer token from environment variable
	bearerToken := os.Getenv("BEARER")
	// Allow only requests which contain the specific Bearer header
	// Allow only GET requests
	identityPublicKeyHex := clientHTTPRequest.Header.Get("Identity")
	identityPublicKeyBytes, identityPublicKeyBytesErr := hex.DecodeString(identityPublicKeyHex)
	if identityPublicKeyBytesErr != nil {
		logError(syslog.LOG_ERR, identityPublicKeyBytesErr)
		http.Error(serverHTTPResponse, identityPublicKeyBytesErr.Error(), 500)
		return
	} // if identityPublicKeyBytesErr != nil
	clientBearerTokenSignatureBytes, clientBearerTokenSignatureBytesErr := base64.StdEncoding.DecodeString(clientHTTPRequest.Header.Get("Bearer"))
	if clientBearerTokenSignatureBytesErr != nil {
		 logError(syslog.LOG_ERR, clientBearerTokenSignatureBytesErr)
		 http.Error(serverHTTPResponse,  clientBearerTokenSignatureBytesErr.Error(), 500)
		 return
	} // if clientBearerTokenSignatureBytesErr != nil
	// If signature validation doesn't pass, fail auth and inform the client
	if !cryptoEd25519.Verify(identityPublicKeyBytes, []byte(bearerToken), clientBearerTokenSignatureBytes) {
		logError(syslog.LOG_INFO, errors.New("Auth failed : " + hex.EncodeToString(identityPublicKeyBytes) + " " + bearerToken + " " + clientHTTPRequest.Header.Get("Bearer")))
		http.Error(serverHTTPResponse, "Auth failed", 403)
		return
	} // if !cryptoEd25519.Verify
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("Bearer auth successful"))
	} // if production == ""
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
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("Websocket connection upgraded"))
	} // if production == ""
	// Initialise the authenticatedClientFirestore object
	authenticatedClient := authenticatedClientFirestore{}
	// Set the websocketConnection so that we can send an error back to the client in case auth fails
	authenticatedClient.websocketConnection = websocketConnection
	// Assign it here to a new variable in case we need to revert to previous version of code 
	authenticatedClient.authenticatedIdentityPublicKeyHex = identityPublicKeyHex
	// Store the connection of an authenticated client so that other clients can interact with him in real time
	authenticatedClientWebSocketConnectionMap[authenticatedClient.authenticatedIdentityPublicKeyHex] = websocketConnection
	// If it's a dev enviroment, log verbose info
	// Continue in the scope of the authenticatedWebsocketConnection to allow for easier testing
	if production == "" {
		logError(syslog.LOG_INFO, errors.New(authenticatedClient.authenticatedIdentityPublicKeyHex+" Entering interactive mode"))
	} // if production == ""
	authenticatedWebsocketConnection(&authenticatedClient)
	// Wait some in case things are still using resources
} // func handleWebSocketConnection

func authenticatedWebsocketConnection(storage storageInterface) {
	authenticatedClient, authenticatedClientErr := storage.getClientDataFromStorage()
	if authenticatedClientErr != nil {
		logError(syslog.LOG_ERR, authenticatedClientErr)
	} // if authenticatedClientErr != nil
	// If it's a dev enviroment, log verbose info
	if production == "" {
		logError(syslog.LOG_INFO, errors.New(authenticatedClient.authenticatedIdentityPublicKeyHex+" Undelivered messages : "+strconv.Itoa(len(authenticatedClient.messagesToBeDelivered))))
	} // if production == ""
	if len(authenticatedClient.messagesToBeDelivered) > 0 {
		// If there are no errors while deliveing the messages to the client
		if deliverMessagesErr := authenticatedClient.deliverMessages(authenticatedClient.messagesToBeDelivered); deliverMessagesErr == nil {
			// @TODO Maybe require the client to echo the message we sent to him as a confirmation that he handled it successfully
			// If there are no errors while deleteing the messages which were delivered
			// If it's a dev enviroment, log verbose info
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(authenticatedClient.authenticatedIdentityPublicKeyHex+" Receiving Messages : "+strconv.Itoa(len(authenticatedClient.messagesToBeDelivered))))
			} // if production == ""
			if deleteFromFieldErr := authenticatedClient.deleteFieldFromStorage("chatMessages", ""); deleteFromFieldErr != nil {
				logError(syslog.LOG_ERR, deleteFromFieldErr)
			} // if deleteFromFieldErr
			// If it's a dev enviroment, log verbose info
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(authenticatedClient.authenticatedIdentityPublicKeyHex+" Deleting Messages from storage : "+strconv.Itoa(len(authenticatedClient.messagesToBeDelivered))))
			} // if production == ""
		} // if deliverMessagesErr == nil
	} // if len(messagesToBeDelivered > 0)
	if production == "" {
		logError(syslog.LOG_INFO, errors.New(authenticatedClient.authenticatedIdentityPublicKeyHex+" Waiting for client event"))
	} // if production == "")
	// Try to process a message from the client
	processedEvents := 0
	requestID, websocketConnectionprocessEventErr := authenticatedClient.processEvent(processedEvents)
	// For as long as we don't enounter an error while processing messages from the client
	for websocketConnectionprocessEventErr == nil {
		// Process messages from the client
		processedEvents++
		requestID, websocketConnectionprocessEventErr = authenticatedClient.processEvent(processedEvents)
	} // for websocketConnectionprocessEventErr == nil
	// Once we enounter an error while processing messages from the client
	// Log the error we encountered
	logError(syslog.LOG_ERR, websocketConnectionprocessEventErr)
	// If there is an error while sending the error to the client, log the error
	if writeMessageErr := authenticatedClient.sendErrorToClient(requestID); writeMessageErr != nil {
		logError(syslog.LOG_ERR, writeMessageErr)
	} // if writeMessageErr
	logError(syslog.LOG_INFO, errors.New("terminating websocket connection to client"))
	// Close the websocket connection
	authenticatedClient.websocketConnection.Close()
	delete(authenticatedClientWebSocketConnectionMap, authenticatedClient.authenticatedIdentityPublicKeyHex)
	return
	// Read first message from client
} // func authenticatedWebsocketConnection

func (a *authenticatedClientFirestore) sendErrorToClient(requestID string) error {
	// Create a protobuf message structure to send back to the client
	var messageToClientProtobuf backendProtobuf.BackendMessage
	// Set the request id from the message that caused the error
	messageToClientProtobuf.RequestID = requestID
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

func (a *authenticatedClientFirestore) processEvent(eventsProcessed int) (string, error) {
	// Initialize an empty variable to hold the protobuf message
	var messageFromClientProtobuf backendProtobuf.BackendMessage
	// Read a message from a client over the websocket connection
	_, messageFromClientBytes, readMessageErr := a.websocketConnection.ReadMessage()
	// Unmarshal the protobuf bytes from the message we received into our protobuf message structure
	if protoUnmarshalErr := golangProto.Unmarshal(messageFromClientBytes, &messageFromClientProtobuf); protoUnmarshalErr != nil {
		return  uuid.NewV4().String(), protoUnmarshalErr
	}
	// If there is an error while reading the message from client
	if readMessageErr != nil {
		// If it's not a normal connection closure, return an error
		if !gorillaWebSocket.IsCloseError(readMessageErr, gorillaWebSocket.CloseNormalClosure) {
			return  messageFromClientProtobuf.RequestID, readMessageErr
		}
		return messageFromClientProtobuf.RequestID, nil 
	} // if readMessageErr != nil
	// If it's a dev enviroment, log verbose info
	if production == "" {
		logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" Processing client event number : "+strconv.Itoa(eventsProcessed)))
	} // if production == "")

	// Outer master switch, cases are valid if they are true
	switch {
	// In case a message has both a request and a response
	case messageFromClientProtobuf.Request != nil && messageFromClientProtobuf.Response != nil:
		// Return an error as it's not allowed for a message to have both a response and a request at the same time
		return messageFromClientProtobuf.RequestID, errors.New("A message can’t have a response and a request at the same time")
	// If the message is a request
	case messageFromClientProtobuf.Request != nil:
		// In case a requestID is missing from a client request
		if messageFromClientProtobuf.RequestID == "" {
			return messageFromClientProtobuf.RequestID, errors.New("A valid client request should always have a RequestID")
		} // if messageFromClientProtobuf.RequestID
		// Inner switch in case we have a Request from client, cases are valid if they are true
		switch {
		case messageFromClientProtobuf.Request.SignedPreKey != nil :
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Request.SignedPreKey event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			// Temporary solution for processing a signedPreKey from client
			var preKey backendProtobuf.PreKey
			if protoUnmarshalErr := golangProto.Unmarshal(messageFromClientProtobuf.Request.SignedPreKey, &preKey); protoUnmarshalErr != nil {
				return messageFromClientProtobuf.RequestID, protoUnmarshalErr
			} // if protoUnmarshalErr
			persistSignedPreKeyFromClientErr := a.persistSignedPreKeyFromClient(&preKey)
			if persistSignedPreKeyFromClientErr == nil {
				if confirmationErr := sendConfirmationToClient(messageFromClientProtobuf.RequestID, a.websocketConnection); confirmationErr != nil {
					return messageFromClientProtobuf.RequestID, confirmationErr
				} // if confirmationErr
				// If we are not in a production environment, verbose log the signedPreKey persistance
				if production == "" {
					logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" Persisted signedPreKey with id : "+fmt.Sprint(messageFromClientProtobuf.Response.SignedPreKey.TimeStamp)+" which belongs to : "+hex.EncodeToString(messageFromClientProtobuf.Response.SignedPreKey.IdentityKey)))
				} // if production == ""
			} // if persistSignedPreKeyFromClientErr == nil
			return messageFromClientProtobuf.RequestID, persistSignedPreKeyFromClientErr
		case messageFromClientProtobuf.Request.Messages != nil:
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Request.Messages event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			for _, singleMessage := range messageFromClientProtobuf.Request.Messages {
				// Store the intendedMessageReciepint in a variable to avoid calling hex.EncodeToString multiple times
				intendedMessageReciepient := hex.EncodeToString(singleMessage.Receiver)
				// If the intended message recipient has an active connection to the backend
				if websocketConnectionMessageRecipient, exists := authenticatedClientWebSocketConnectionMap[intendedMessageReciepient]; exists {
					if production == "" {
						logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" Attempting to send a real time message to : "+intendedMessageReciepient))
					} // if production == ""
					// // Attempt to send the messages messages in real time to the intendedMessageRecipient, in case of an error
					if writeMessageErr := websocketConnectionMessageRecipient.WriteMessage(gorillaWebSocket.BinaryMessage, messageFromClientBytes); writeMessageErr != nil {
						// Log the error and continue persisting the message to the backend
						logError(syslog.LOG_ERR, writeMessageErr)
						// Else in case of no error
					} else {
						if production == "" {
							logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" Not persisting message on backend as successfuly sent it in real time to : "+intendedMessageReciepient))
						} // if production == ""
						// Return nil and don't persist the message to the backend
						if confirmationErr := sendConfirmationToClient(messageFromClientProtobuf.RequestID, a.websocketConnection); confirmationErr != nil {
							return messageFromClientProtobuf.RequestID, confirmationErr
						} // if confirmationErr
						return  messageFromClientProtobuf.RequestID, writeMessageErr
					} // else
				} // if websocketConnectionMessageRecipient, exists
			} // for _, singleMessage
			persistChatMessagesFromClientErr := a.persistChatMessagesFromClient(messageFromClientProtobuf.Request.Messages)
			// If there was no error while persisting the messages
			if persistChatMessagesFromClientErr == nil {
				if confirmationErr := sendConfirmationToClient(messageFromClientProtobuf.RequestID, a.websocketConnection); confirmationErr != nil {
					return messageFromClientProtobuf.RequestID, confirmationErr
				} // if confirmationErr
				// For each message that was persisted
				for _, singleMessageFromClient := range messageFromClientProtobuf.Request.Messages {
					// If we are in dev mode, log each persisted event
					if production == "" {
						logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" Persisted message meant for offline client : "+hex.EncodeToString(singleMessageFromClient.Receiver)))
					} // if production == ""
				} // for singleMessageFromClient := range messageFromClientProtobuf.Request.Messages {
			} // persistChatMessagesFromClientErr
			// If there is an error while reading the message from client
			return messageFromClientProtobuf.RequestID, persistChatMessagesFromClientErr
		// @TODO wait for @Gross input on message states
		case messageFromClientProtobuf.Request.MessageStateChange != nil:
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Request.MessageStateChange event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			fmt.Println(messageFromClientProtobuf.Request.MessageStateChange, "MessageStateChange")
		case messageFromClientProtobuf.Request.NewOneTimePreKeys != 0:
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Request.NewOneTimePreKeys event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			return messageFromClientProtobuf.RequestID, errors.New("Only backend is allowed to request NewOneTimePreKeys")
		case messageFromClientProtobuf.Request.PreKeyBundle != nil:
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Request.PreKeyBundle event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			// Create a new instance of authenticatedClientFirestore to assist us with fetching the requested preKeyBundle
			authenticatedClientForPreKeyBundle := authenticatedClientFirestore{}
			// Use the already existing websocket connection which is expecting a respond to their request for the preKeyBundle
			authenticatedClientForPreKeyBundle.websocketConnection = a.websocketConnection
			// Requesting a pre key bundle consumes a oneTimePreKey thus we note it down
			usedOneTimePreKey, deliverRequestedPreKeyBundleErr := authenticatedClientForPreKeyBundle.deliverRequestedPreKeyBundle(messageFromClientProtobuf.Request.PreKeyBundle, messageFromClientProtobuf.RequestID)
			// If there was no error while delivering the preKeyBundle, delete the consumed oneTimePreKey
			if deliverRequestedPreKeyBundleErr == nil {
				if production == "" {
					logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" Delivered preKeyBundle which belongs to : "+hex.EncodeToString(messageFromClientProtobuf.Request.PreKeyBundle)))
					logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" Deleted consumed oneTimePreKey with id : "+usedOneTimePreKey+" which belongs to : "+hex.EncodeToString(messageFromClientProtobuf.Request.PreKeyBundle)))
				} // if production == ""
				// Delete the oneTimePreKey which got consumed
				authenticatedClientForPreKeyBundle.deleteFieldFromStorage("oneTimePreKeys", usedOneTimePreKey)
			} // if deliverRequestedPreKeyBundleErr
			return messageFromClientProtobuf.RequestID, deliverRequestedPreKeyBundleErr
		case messageFromClientProtobuf.Request.Auth != nil:
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Request.Auth event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			return messageFromClientProtobuf.RequestID, errors.New("Backend should request authentication, not the client")
		} // Inner switch {
	// If the message is a response
	case messageFromClientProtobuf.Response != nil:
		// Inner switch in case we have a Response from client, cases are valid if they are true
		switch {
		case messageFromClientProtobuf.Response.Auth != nil:
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Response.Auth event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			return messageFromClientProtobuf.RequestID, errors.New("Authentication should not be handled here")
		case messageFromClientProtobuf.Response.OneTimePrekeys != nil:
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Response.OneTimePrekeys event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			persistOneTimePreKeysFromClientErr := a.persistOneTimePreKeysFromClient(messageFromClientProtobuf.Response.OneTimePrekeys)
			// If no error was encountered while persisting the oneTimePreKeys from the client
			if persistOneTimePreKeysFromClientErr == nil {
				if confirmationErr := sendConfirmationToClient(messageFromClientProtobuf.RequestID, a.websocketConnection); confirmationErr != nil {
					return messageFromClientProtobuf.RequestID, confirmationErr
				} // if confirmationErr
				// If we are not in a production environment, verbose log each oneTimePreKey persistance
				if production == "" {
					for _, oneTimePreKeyFromClient := range messageFromClientProtobuf.Response.OneTimePrekeys {
						logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" Persisted oneTimePreKey with id : "+fmt.Sprint(oneTimePreKeyFromClient.TimeStamp)+" which belongs to : "+hex.EncodeToString(oneTimePreKeyFromClient.IdentityKey)))
					} //for _, oneTimePreKeyFromClient := range messageFromClientProtobuf.Response.OneTimePrekeys {
				} // if production == ""
			} // if persistOneTimePreKeysFromClient == nil
			return messageFromClientProtobuf.RequestID, persistOneTimePreKeysFromClientErr
		case messageFromClientProtobuf.Response.PreKeyBundle != nil:
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Response.PreKeyBundle event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			return messageFromClientProtobuf.RequestID, errors.New("Only backend is allowed to provide a PreKeyBundle")
		case messageFromClientProtobuf.Response.SignedPreKey != nil:
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" messageFromClientProtobuf.Response.SignedPreKey event : "+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			persistSignedPreKeyFromClientErr := a.persistSignedPreKeyFromClient(messageFromClientProtobuf.Response.SignedPreKey)
			if persistSignedPreKeyFromClientErr == nil {
				if confirmationErr := sendConfirmationToClient(messageFromClientProtobuf.RequestID, a.websocketConnection); confirmationErr != nil {
					return messageFromClientProtobuf.RequestID, confirmationErr
				} // if confirmationErr
				// If we are not in a production environment, verbose log the signedPreKey persistance
				if production == "" {
					logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" Persisted signedPreKey with id : "+fmt.Sprint(messageFromClientProtobuf.Response.SignedPreKey.TimeStamp)+" which belongs to : "+hex.EncodeToString(messageFromClientProtobuf.Response.SignedPreKey.IdentityKey)))
				} // if production == ""
			} // if persistSignedPreKeyFromClientErr == nil
			return messageFromClientProtobuf.RequestID, persistSignedPreKeyFromClientErr
		} // Inner switch in case we have a Response from client

	// The only time it should reach the default case is when both messageFromClientProtobuf.Request == nil && messageFromClientProtobuf.Response == nil
	default:
		if production == "" {
			logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+" default event : "+strconv.Itoa(eventsProcessed)))
		} // if production == "")
		if messageFromClientProtobuf.Error != "" {
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+` default messageFromClientProtobuf.Error != "" : `+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			return messageFromClientProtobuf.RequestID, errors.New(messageFromClientProtobuf.Error)
		}

		if messageFromClientProtobuf.RequestID != "" {
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+` default messageFromClientProtobuf.RequestID != "" : `+strconv.Itoa(eventsProcessed)))
			} // if production == "")
		}

		if messageFromClientProtobuf.RequestID == "" {
			if production == "" {
				logError(syslog.LOG_INFO, errors.New(a.authenticatedIdentityPublicKeyHex+` default messageFromClientProtobuf.RequestID == "" : `+strconv.Itoa(eventsProcessed)))
			} // if production == "")
			a.websocketConnection.Close()
			delete(authenticatedClientWebSocketConnectionMap, a.authenticatedIdentityPublicKeyHex)
		}
	}
	return messageFromClientProtobuf.RequestID, nil
} // func processEvent

func (a *authenticatedClientFirestore) deliverRequestedPreKeyBundle(requestedPreKeyBundle []byte, clientRequestID string) (string, error) {
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
	// Use the same requestID from the client in our response
	messageToClientProtobuf.RequestID = clientRequestID
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
		return "", messageToClientProtobufErr
	} // if protobufMessageToClientErr != nil {
	// Send our message over the websocket connection
	// Restore the temporary snapshot of the original authenticatedClientFirestore
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
	// Add a unique request id 
	messageToClientProtobuf.RequestID = uuid.NewV4().String()
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
	} // if messageToClientProtobufErr
	// Send the mashalled protobuf message structure over the websocket connection
	if writeMessageErr := a.websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientProtobufBytes); writeMessageErr != nil {
		return writeMessageErr
	} // if writeMessageErr
	return nil
} // func deliverMessages

func requestAuth(websocketConnection *gorillaWebSocket.Conn) ([]byte, string, error) {
	// Initialize an empty Message structure
	messageFromClient := backendProtobuf.BackendMessage{}
	// Initialize an empty Response structure
	messageFromClient.Response = &backendProtobuf.BackendMessage_Response{}
	// Initialize an empty Message structure
	messageToClient := backendProtobuf.BackendMessage{}
	// Initialize an empty Request structure
	messageToClient.Request = &backendProtobuf.BackendMessage_Request{}
	// Add a unique request id 
	messageToClient.RequestID = uuid.NewV4().String()
	// Initialize an empty Auth structure
	messageToClient.Request.Auth = &backendProtobuf.BackendMessage_Auth{}
	// Create a byte slice to store our random bytes
	backendRandomBytes := make([]byte, 4)
	// Read random bytes into our slice, in case of an error, return it
	if _, randomBytesErr := rand.Read(backendRandomBytes); randomBytesErr != nil {
		return nil, messageToClient.RequestID, randomBytesErr
	} // if randomBytesErr != nil
	// Set the byte sequence that the client needs to sign
	messageToClient.Request.Auth.ToSign = backendRandomBytes
	// Prepare the data to be sent to the client
	messageToClientBytes, messageToClientBytesErr := golangProto.Marshal(&messageToClient)
	// If there is an error while trying to perform protobuf marshaling, terminate the connection
	if messageToClientBytesErr != nil {
		return nil, messageToClient.RequestID, messageToClientBytesErr
	} // if messageToClientBytesErr != nil
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("Sending .Auth.ToSign over websocket to client"))
	} // if production == ""
	// Send the protobuf data to the client containing the sequence of bytes he needs to sign
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("Exact message sent : " + base64.StdEncoding.EncodeToString(messageToClientBytes)))
	} // if production == ""
	if writeMessageErr := websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientBytes); writeMessageErr != nil {
		return nil, messageToClient.RequestID, writeMessageErr
	} // if writeMessageErr
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("Sent .Auth.ToSign successfuly to client"))
	} // if production == ""
	// Read the response from the client which should contain his IdenetityPublicKey and the signed byte sequence
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("About to read Auth response from client"))
	} // if production == ""
	_, messageFromClientProto, readMessageErr := websocketConnection.ReadMessage()
	// In case of an error, terminate the connection
	if readMessageErr != nil {
		return nil, messageToClient.RequestID, readMessageErr
	}
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("Successfully read Auth response from client"))
	} // if production == ""
	// Unmarshal the response from the client into our protobuf Auth structure, and in case of an error, terminate the connection
	if protoUnmarshalErr := golangProto.Unmarshal(messageFromClientProto, &messageFromClient); protoUnmarshalErr != nil {
		return nil, messageToClient.RequestID, protoUnmarshalErr
	} // if protoUnmarshalErr
	// Create a [32]byte{} identityPublicKey to satisfy cryptoEd25519.Verify() type requirements
	identityPublicKey := [32]byte{}
	// Create a [64]byte{} byteSequenceToSignSignature to satisfy cryptoEd25519.Verify() type requirements
	byteSequenceToSignSignature := [64]byte{}
	// Make sure that Auth has be filled by client to avoid potential panics
	if messageFromClient.Response.Auth == nil {
		return nil, messageToClient.RequestID, errors.New("Auth must not be empty")
	} // if messageFromClient.Response.Auth
	// Create a string representation of the Identity Public Key
	identityPublicKeyBytes := messageFromClient.Response.Auth.IdentityPublicKey
	// Get the byte sequence which was signed by the client
	byteSequenceThatClientSigned := messageFromClient.Response.Auth.ToSign
	if len(byteSequenceThatClientSigned) != 8 {
		return nil, messageToClient.RequestID, errors.New("Signed byte sequence should be exactly 8 bytes")
	} // if len(byteSequenceThatClientSigned) != 8
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("OK Auth response from client has exactly 8 bytes"))
	} // if production == ""
	// Check if the byte sequence that was signed by the client contains the initial bytes we sent to the client
	if !bytes.HasPrefix(byteSequenceThatClientSigned, backendRandomBytes) {
		// If the client has modified the bytes we sent, return an error pointing out that this behavior is not allowed
		return nil, messageToClient.RequestID, errors.New("Client is only allowed to append a byte sequence, and not to modify the one which was sent")
	} // if !bytes.HasPrefix
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("OK Auth response from client appended 4 bytes"))
	} // if production == ""
	// Make sure that the identityPublicKey is exactly 32 bytes
	if len(identityPublicKeyBytes) != 32 {
		return nil, messageToClient.RequestID, errors.New("identityPublicKey should be exactly 32 bytes")
	} // if len(identityPublicKey) != 32
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("OK Auth response from client identityPublicKey is exactly 32 bytes"))
	} // if production == ""
	// Fill the newly created identityPublicKey with the hex decoded representation of the IdentityPublicKey contained in the response from the client
	copy(identityPublicKey[:], identityPublicKeyBytes)
	// Make sure that the Signature is exactly 64 bytes
	if len(messageFromClient.Response.Auth.Signature) != 64 {
		return nil, messageToClient.RequestID, errors.New("Signature should be exactly 64 bytes")
	} // if len(messageFromClient.Response.Auth.Signature) != 32
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("OK Auth response from client Signature is exactly 64 bytes"))
	} // if production == ""
	// Fill the newly created byteSequenceToSignSignature with the Signature contained in the response from the client
	copy(byteSequenceToSignSignature[:], messageFromClient.Response.Auth.Signature)
	// Verify the validity of the signature using cryptoEd25519.Verify()
	if cryptoEd25519.Verify(identityPublicKey[:], byteSequenceThatClientSigned, byteSequenceToSignSignature[:]) {
		if production == "" {
			logError(syslog.LOG_INFO, errors.New("OK Auth signature was verified, echoing authentication attempt back to the client so that he knows it was successful"))
		} // if production == ""
		// Send confirmation to the client
		if confirmationErr := sendConfirmationToClient(messageToClient.RequestID, websocketConnection); confirmationErr != nil {
			return nil, messageToClient.RequestID, confirmationErr
		} // if confirmationErr
		if production == "" {
			logError(syslog.LOG_INFO, errors.New("OK Auth echoing authentication attempt succeeded"))
		} // if production == ""
		// Return the identityPublicKey of the authenticated client
		return identityPublicKeyBytes, messageToClient.RequestID, nil 
	} // if cryptoEd25519.Verify
	// If cryptoEd25519.Verify() failed to verify the signature, return a matching reponse
	return nil, messageToClient.RequestID, errors.New("Invalid Signature")
} // func requestAuth

func sendConfirmationToClient(requestID string, websocketConnection *gorillaWebSocket.Conn) error {
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("Trying to send confirmation to client that there wasn't an error while processing " + requestID))
	} // if production == ""
	// Create a structure to send to client
	var messageToClientProtobuf backendProtobuf.BackendMessage
	// Set the request id which completeed successfully
	messageToClientProtobuf.RequestID =  requestID
	// Marshal using protobuf to conform to what client is expecting from us
	messageToClientProtobufBytes, messageToClientProtobufBytesErr := golangProto.Marshal(&messageToClientProtobuf);
	if messageToClientProtobufBytesErr != nil {
		return messageToClientProtobufBytesErr
		if production == "" {
			logError(syslog.LOG_INFO, errors.New("Protobuf marshal error encountered while sending confirmation to client in regards to " + requestID))
		} // if production == ""
	} // if messageToClientProtobufBytes
	// Send the .RequestID back to the client so that he knows it was successful
	if writeMessageError := websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientProtobufBytes); writeMessageError != nil {
		if production == "" {
			logError(syslog.LOG_INFO, errors.New("WriteMessageError encountered while sending confirmation to client in regards to  " + requestID))
		} // if production == ""
		return writeMessageError
	} // if writeMessageError
	if production == "" {
		logError(syslog.LOG_INFO, errors.New("Successfully sent confirmation to client that there wasn't an error while processing " + requestID))
	} // if production == ""
	return nil
} // func sendConfirmationToClient
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

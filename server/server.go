package chatbackend

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"

	backendProtobuf "github.com/Bit-Nation/protobuffers"
	golangProto "github.com/golang/protobuf/proto"
	gorillaMux "github.com/gorilla/mux"
	gorillaWebSocket "github.com/gorilla/websocket"
	cryptoEd25519 "golang.org/x/crypto/ed25519"
)

// @TODO REPLACE WITH GOOGLE DATASTORE
// Proof of concept backend storage
var multiUserChatMessage = make(map[string][][]byte)
var multiUserProfileStore = make(map[string][]byte)
var multiUserSignedPreKeyStore = make(map[string][]byte)
var multiUserOneTimePreKeys = make(map[string][][]byte)

// StartWebsocketServer starts the websocket server
func StartWebsocketServer() {
	multiUserProfileStore["22cfd1af5798544287cbf7721a0a4ebc2506d6f4df05413355a7f5cc86740724"] = []byte{10, 3, 66, 111, 98, 18, 5, 69, 97, 114, 116, 104, 26, 6, 98, 97, 115, 101, 54, 52, 34, 32, 34, 207, 209, 175, 87, 152, 84, 66, 135, 203, 247, 114, 26, 10, 78, 188, 37, 6, 214, 244, 223, 5, 65, 51, 85, 167, 245, 204, 134, 116, 7, 36, 42, 33, 2, 112, 86, 251, 69, 250, 221, 106, 218, 195, 167, 212, 229, 95, 13, 127, 156, 213, 63, 112, 93, 97, 163, 22, 140, 10, 129, 15, 99, 86, 187, 115, 196, 50, 32, 126, 223, 126, 93, 92, 179, 254, 62, 209, 108, 209, 75, 184, 251, 115, 230, 54, 254, 106, 11, 82, 61, 34, 47, 24, 11, 41, 186, 154, 145, 202, 97, 56, 180, 218, 177, 218, 5, 64, 2, 74, 64, 60, 237, 190, 135, 89, 152, 249, 49, 184, 64, 107, 107, 84, 70, 94, 195, 44, 202, 42, 211, 33, 168, 210, 185, 163, 120, 172, 234, 13, 50, 67, 143, 7, 255, 62, 69, 113, 89, 41, 83, 161, 146, 57, 13, 78, 196, 150, 249, 101, 59, 117, 129, 49, 137, 172, 66, 241, 104, 187, 41, 83, 129, 231, 3, 82, 65, 172, 68, 236, 179, 119, 160, 208, 100, 212, 101, 36, 155, 38, 5, 104, 222, 95, 90, 182, 38, 76, 55, 189, 139, 61, 253, 129, 97, 250, 254, 0, 139, 86, 225, 112, 3, 88, 56, 70, 147, 39, 54, 136, 131, 210, 183, 72, 11, 239, 64, 47, 168, 20, 11, 197, 204, 64, 166, 110, 184, 163, 152, 253, 7, 1}
	// Create new gorillaRouter
	gorillaRouter := gorillaMux.NewRouter()
	// Bind an endpoint path to handleWebsocketConnection
	gorillaRouter.HandleFunc("/chat", HandleWebsocketConnection)
	// Listen on a specific port for incoming connections
	listenAndServeErr := http.ListenAndServe(":8080", gorillaRouter)
	// If there is an error while setting up
	if listenAndServeErr != nil {
		// Panic and show us the error
		log.Fatal("ListenAndServe: " + listenAndServeErr.Error())
	} // if listenAndServeErr != nil {
} // func startWebsocketServer

// HandleWebsocketConnection decides what happens when a client establishes a websocket connection to the server
func HandleWebsocketConnection(serverHTTPResponse http.ResponseWriter, clientHTTPRequest *http.Request) {
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
	// Require successful authentication before allowing a client to send a message
	authenticatedIdentityPublicKeyHexClient, websocketConnectionrequestAuthErr := requestAuth(websocketConnection)
	if websocketConnectionrequestAuthErr != nil {
		// If the authentication failed, terminate the websocket connection to the client
		log.Println("Authentication Failed:", websocketConnectionrequestAuthErr)
		websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, []byte(websocketConnectionrequestAuthErr.Error()))
		log.Println("Terminating websocket connection to client.")
		// Close the websocket connection
		websocketConnection.Close()
		return
	}
	// Check if there are pending messages to be delivered when the client comes back online
	if messagesToBeDelivered, ok := multiUserChatMessage[authenticatedIdentityPublicKeyHexClient]; ok {
		deliverMessages(websocketConnection, messagesToBeDelivered)
	} // if messagesToBeDelivered

	websocketConnectionProcessMessageErr := processMessage(websocketConnection, authenticatedIdentityPublicKeyHexClient)
	for websocketConnectionProcessMessageErr == nil {
		websocketConnectionProcessMessageErr = processMessage(websocketConnection, authenticatedIdentityPublicKeyHexClient)
	}
	// Close the websocket connection
	websocketConnection.Close()
	return
	// Read first message from client
} // func handleWebsocketConnection

func processMessage(websocketConnection *gorillaWebSocket.Conn, authenticatedIdentityPublicKeyHexClient string) error {
	// Initialize an empty variable to hold the protobuf message
	var messageFromClientProtobuf backendProtobuf.BackendMessage
	// Read a message from a client over the websocket connection
	_, messageFromClientBytes, readMessageErr := websocketConnection.ReadMessage()
	if readMessageErr != nil {
		// If there is an error while reading the response from the client, return the error
		return readMessageErr
	}
	// Unmarshal the protobuf bytes from the message we received into our protobuf message structure
	protoUnmarshalErr := golangProto.Unmarshal(messageFromClientBytes, &messageFromClientProtobuf)
	if protoUnmarshalErr != nil {
		// If there is an error while unmarshaling the response from the client, return the error
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
		// Inner switch in case we have a Request from client, cases are valid if they are true
		switch {
		case messageFromClientProtobuf.Request.Messages != nil:
			handleMessageFromClient(websocketConnection, messageFromClientProtobuf.Request.Messages)
		// @TODO wait for @Gross input on message states
		case messageFromClientProtobuf.Request.MessageStateChange != nil:
			fmt.Println(messageFromClientProtobuf.Request.MessageStateChange, "MessageStateChange")
		case messageFromClientProtobuf.Request.NewOneTimePreKeys != 0:
			return errors.New("Only backend is allowed to request NewOneTimePreKeys")
		case messageFromClientProtobuf.Request.PreKeyBundle != nil:
			deliverRequestedPreKeyBundle(websocketConnection, messageFromClientProtobuf.Request.PreKeyBundle)
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
			persistOneTimeKeysFromClient(websocketConnection, messageFromClientProtobuf.Response.OneTimePrekeys)
		case messageFromClientProtobuf.Response.PreKeyBundle != nil:
			return errors.New("Only backend is allowed to provide a PreKeyBundle")
		case messageFromClientProtobuf.Response.SignedPreKey != nil:
			persistSignedPreKeyFromClient(websocketConnection, messageFromClientProtobuf.Response.SignedPreKey)
		} // Inner switch in case we have a Response from client

	// The only time it should reach the default case is when both messageFromClientProtobuf.Request == nil && messageFromClientProtobuf.Response == nil
	default:
		if messageFromClientProtobuf.Error != "" {
			// @TODO HANDLE DIFFERENT TYPES OF ERRORS
		}

		if string(messageFromClientProtobuf.RequestID) != "" {
			// @TODO RESPOND TO THIS REQUEST
		}

		if string(messageFromClientProtobuf.RequestID) == "" {
			// @TODO AKNOWLEDGE THAT EVERYTHING IS OK
		}
	}
	return nil
} // func processMessage

func persistOneTimeKeysFromClient(websocketConnection *gorillaWebSocket.Conn, oneTimePreKeysFromClient []*backendProtobuf.PreKey) error {
	// For each one time pre key received from client
	for _, oneTimePreKeyFromClient := range oneTimePreKeysFromClient {
		// Create a hex representation of the IdentityKey of the client
		clientIdentityKeyHex := hex.EncodeToString(oneTimePreKeyFromClient.IdentityKey)
		// Use protobuf to marshal the one time pre key into bytes so that we can store it easily
		oneTimePreKeyFromClientProtobufBytes, protoMarshalErr := golangProto.Marshal(oneTimePreKeyFromClient)
		// If there is an error while marshalling the one time pre key from the client
		if protoMarshalErr != nil {
			// Return the error
			return protoMarshalErr
		}
		// Store the one time pre key from the client
		multiUserOneTimePreKeys[clientIdentityKeyHex] = append(multiUserOneTimePreKeys[clientIdentityKeyHex], oneTimePreKeyFromClientProtobufBytes)
		// Signal to the client that the one time pre key has been persisted
		writeMessageError := websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, oneTimePreKeyFromClientProtobufBytes)
		// If there is an error while sending a message to a client
		if writeMessageError != nil {
			return writeMessageError
		} // if writeMessageError != nil
	}
	return nil
}

func persistSignedPreKeyFromClient(websocketConnection *gorillaWebSocket.Conn, signedPreKeyFromClient *backendProtobuf.PreKey) error {
	// Create a hex representation of the IdentityKey of the client
	clientIdentityKeyHex := hex.EncodeToString(signedPreKeyFromClient.IdentityKey)
	// Use protobuf to marshal the signed pre key into bytes so that we can store it easily
	signedPreKeyFromClientProtobufBytes, protoMarshalErr := golangProto.Marshal(signedPreKeyFromClient)
	// If there is an error while marshalling the signed pre key from the client
	if protoMarshalErr != nil {
		// Return the error
		return protoMarshalErr
	}
	// Store the SignedPreKey from the client
	multiUserSignedPreKeyStore[clientIdentityKeyHex] = signedPreKeyFromClientProtobufBytes
	// Signal to the client that the SignedPreyKey has been persisted
	writeMessageError := websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, signedPreKeyFromClientProtobufBytes)
	// If there is an error while sending a message to a client
	if writeMessageError != nil {
		return writeMessageError
	} // if writeMessageError != nil

	return nil
}

func handleMessageFromClient(websocketConnection *gorillaWebSocket.Conn, messagesFromClient []*backendProtobuf.ChatMessage) error {
	// For each message received from client
	for _, singleMessageFromClient := range messagesFromClient {
		// Use protobuf to marshal the message into bytes so that we can store it easily
		chatMessageProtobufBytes, chatMessageProtobufError := golangProto.Marshal(singleMessageFromClient)
		// If there is an error while marshaling the individual message from the client
		if chatMessageProtobufError != nil {
			// Return the error
			return chatMessageProtobufError
		} // if chatMessageProtobufError != nil
		// Convert the identityPublicKey of the intented recipient of the message into a string so that it's easier to use
		messageReceiverString := string(singleMessageFromClient.Receiver)
		// Use the string representation of the identityPublicKey as part of our backend storage
		multiUserChatMessage[messageReceiverString] = append(multiUserChatMessage[messageReceiverString], chatMessageProtobufBytes)
		// Echo back the same message we received from the client back to him so that we inform him that the message has been persisted
		writeMessageError := websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, chatMessageProtobufBytes)
		// If there is an error while sending a message to a client
		if writeMessageError != nil {
			return writeMessageError
		} // if writeMessageError != nil
	} // for _, singleMessageFromClient
	return nil
} // func handleMessageFromClient

func deliverRequestedPreKeyBundle(websocketConnection *gorillaWebSocket.Conn, requestedPreKeyBundle []byte) {
	// Create a string representation of the publicKey associated with the user in the preKeyBundle request
	requestedPreKeyBundleString := string(requestedPreKeyBundle)
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
	// If a Profile which matches the client request exists in our backend storage
	if singleUserProfile, ok := multiUserProfileStore[requestedPreKeyBundleString]; ok {
		// Unmarshal it into our PreKeyBundle structure
		protoUnmarshalErr := golangProto.Unmarshal(singleUserProfile, messageToClientProtobuf.Response.PreKeyBundle.Profile)
		// If there is an error with the unmarshalling
		if protoUnmarshalErr != nil {
			// Fill in the error field in the message to client with the error that occured
			messageToClientProtobuf.Error = protoUnmarshalErr.Error()
		} // if protoUnmarshalErr != nil
	} // if singleUserProfile, ok

	// If a SignedPreKey which matches the client request exists in our backend storage
	if singleUserSignedPreKey, ok := multiUserSignedPreKeyStore[requestedPreKeyBundleString]; ok {
		// Unmarshal it into our SignedPreKey structure
		protoUnmarshalErr := golangProto.Unmarshal(singleUserSignedPreKey, messageToClientProtobuf.Response.PreKeyBundle.SignedPreKey)
		if protoUnmarshalErr != nil {
			// Fill in the error field in the message to client with the error that occured
			messageToClientProtobuf.Error = protoUnmarshalErr.Error()
		} // if protoUnmarshalErr != nil
	} // if singleUserSignedPreKey, ok

	// If OneTimePreKeys which match the client request exist in our backend storage
	if singleUserOneTimePreKeys, ok := multiUserOneTimePreKeys[requestedPreKeyBundleString]; ok {
		// Create a variable to temporarily store a single OneTimePreKey
		var singleUserOneTimePreKey []byte
		// Take the first OneTimePreKey from the slice
		for _, singleUserOneTimePreKey = range singleUserOneTimePreKeys {
			// Break out from the for loop after taking the first OneTimePreKey from the slice
			break
		} // for _, singleUserOneTimePreKey
		protoUnmarshalErr := golangProto.Unmarshal(singleUserOneTimePreKey, messageToClientProtobuf.Response.PreKeyBundle.OneTimePreKey)
		if protoUnmarshalErr != nil {
			// Fill in the error field in the message to client with the error that occured
			messageToClientProtobuf.Error = protoUnmarshalErr.Error()
		} // if protoUnmarshalErr != nil
	} // if singleUserOneTimePreKeys, ok

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
	websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientProtobufBytes)
	// @TODO HANDLE ERROR HERE?
}

func deliverMessages(websocketConnection *gorillaWebSocket.Conn, messagesToBeDelivered [][]byte) {
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
		protoUnmarshalErr := golangProto.Unmarshal(singleMessageToBeDelivered, &singleMessageToBeDeliveredProtobuf)
		if protoUnmarshalErr != nil {
			// If there is an error
			messageToClientProtobuf.Error = protoUnmarshalErr.Error()
		} // if protoUnmarshalErr != nil {
		// Append the message  to the []*backendProtobuf.ChatMessage{} slice
		messageToClientProtobuf.Request.Messages = append(messageToClientProtobuf.Request.Messages, &singleMessageToBeDeliveredProtobuf)
	} // for _, singleMessageToBeDelivered := range messagesToBeDelivered
	// Marshal the protobuf message structure so that it can be sent to the client over the websocket connection
	messageToClientProtobufBytes, messageToClientProtobufErr = golangProto.Marshal(&messageToClientProtobuf)
	// If we encounter an error while marshaling the protobuf message structure
	if messageToClientProtobufErr != nil {
		// Overwrite the current message structure which caused the error with an empty one in hopes that an empty one wont cause an error
		messageToClientProtobuf = backendProtobuf.BackendMessage{}
		// Append the error that we encountered when trying to protobuf marshal the original message structure
		messageToClientProtobuf.Error = messageToClientProtobufErr.Error()
		// Attempt to marshal the protobuf message structure again which only contains the error we originally encountered so that the client knows there was an error
		messageToClientProtobufBytes, messageToClientProtobufErr = golangProto.Marshal(&messageToClientProtobuf)
	}
	// Send the mashalled protobuf message structure over the websocket connection
	websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientProtobufBytes)
	// @TODO HANDLE ERROR HERE?
} // func deliverMessages

func requestAuth(websocketConnection *gorillaWebSocket.Conn) (string, error) {
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
	// Read random bytes into our slice
	_, randomBytesErr := rand.Read(backendRandomBytes)
	// If there is an error reading random bytes
	if randomBytesErr != nil {
		return "", randomBytesErr
	} // if randomBytesErr != nil
	// Set the byte sequence that the client needs to sign
	messageToClient.Request.Auth.ToSign = backendRandomBytes
	// Prepare the data to be sent to the client
	messageToClientBytes, messageToClientBytesErr := golangProto.Marshal(&messageToClient)
	if messageToClientBytesErr != nil {
		// If there is an error while trying to perform protobuf marshaling, terminate the connection
		return "", messageToClientBytesErr
	} // if messageToClientBytesErr != nil
	// Send the protobuf data to the client containing the sequence of bytes he needs to sign
	websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageToClientBytes)
	// Read the response from the client which should contain his IdenetityPublicKey and the signed byte sequence
	_, messageFromClientProto, readMessageErr := websocketConnection.ReadMessage()
	if readMessageErr != nil {
		// If there is an error while reading the response from the client, terminate the connection
		return "", readMessageErr
	}
	// Unmarshal the response from the client into our protobuf Auth structure
	protoUnmarshalErr := golangProto.Unmarshal(messageFromClientProto, &messageFromClient)
	if protoUnmarshalErr != nil {
		// If there is an error while unmarshaling the response from the client, terminate the connection
		return "", protoUnmarshalErr
	}
	// Create a [32]byte{} identityPublicKey to satisfy cryptoEd25519.Verify() type requirements
	identityPublicKey := [32]byte{}
	// Create a [64]byte{} signedByteSequenceFromClient to satisfy cryptoEd25519.Verify() type requirements
	signedByteSequenceFromClient := [64]byte{}
	// Create a string representation of the Identity Public Key
	identityPublicKeyString := string(messageFromClient.Response.Auth.IdentityPublicKey)
	// Decode the hex representation of the identityPublicKey here as transmitting it over the network without hex encoding can cause issues with some clients
	identityPublicKeyDecoded, identityPublicKeyDecodedErr := hex.DecodeString(identityPublicKeyString)
	if identityPublicKeyDecodedErr != nil {
		// If there is an error while decoding the hex identity public key, terminate the connection
		return "", identityPublicKeyDecodedErr
	}
	// Get the byte sequence which was signed by the client
	byteSequenceThatClientSigned := messageFromClient.Response.Auth.ToSign
	// Check if the byte sequence that was signed by the client contains the initial bytes we sent to the client
	if !bytes.HasPrefix(byteSequenceThatClientSigned, backendRandomBytes) {
		// If the client has modified the bytes we sent, return an error pointing out that this behavior is not allowed
		return "", errors.New("Client is only allowed to append a byte sequence, and not to modify the one which was sent")
	}
	// Fill the newly created identityPublicKey with the hex decoded representation of the IdentityPublicKey contained in the response from the client
	copy(identityPublicKey[:], identityPublicKeyDecoded)
	// Fill the newly created signedByteSequenceFromClient with the Signature contained in the response from the client
	copy(signedByteSequenceFromClient[:], messageFromClient.Response.Auth.Signature)
	// Verify the validity of the signature using cryptoEd25519.Verify()
	if cryptoEd25519.Verify(identityPublicKey[:], byteSequenceThatClientSigned, signedByteSequenceFromClient[:]) {
		// If the signed byte sequence from client has a valid signature, echo the authentication attempt back to the client so that he knows it was successful
		writeMessageError := websocketConnection.WriteMessage(gorillaWebSocket.BinaryMessage, messageFromClientProto)
		// If there is an error while sending a message to a client
		if writeMessageError != nil {
			// Return the error
			return "", writeMessageError
		}
		// Return the identityPublicKey of the authenticated client
		return identityPublicKeyString, nil
	}
	// If cryptoEd25519.Verify() failed to verify the signature, return a matching reponse
	return "", errors.New("Invalid Signature")
} // func requestAuth
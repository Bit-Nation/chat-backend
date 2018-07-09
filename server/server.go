package chatbackend

import (
	"encoding/hex"
	"errors"
	"log"
	"net/http"

	"github.com/agl/ed25519"
	backendProtobuf "github.com/borjantrajanoski/protobuffers"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

func StartWebsocketServer() {
	// Create new gorillaRouter
	gorillaRouter := mux.NewRouter()
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

func HandleWebsocketConnection(serverHTTPResponse http.ResponseWriter, clientHTTPRequest *http.Request) {
	// Allow only requests which contain the specific Bearer header
	// Allow only GET requests
	if clientHTTPRequest.Header.Get("Bearer") != "5d41402abc4b2a76b9719d911017c592" || clientHTTPRequest.Method != "GET" {
		// If a client is missing the Bearer header or is using a different method than GET return a Forbidden error
		http.Error(serverHTTPResponse, "Forbidden", 403)
		return
	}
	// Prepare to upgrade the HTTP connection to a WebSocket connection
	httpConnectionUpgrader := websocket.Upgrader{}
	// Upgrade the HTTP connection to a WebSocket connection
	websocketConnection, websocketConnectionErr := httpConnectionUpgrader.Upgrade(serverHTTPResponse, clientHTTPRequest, nil)
	if websocketConnectionErr != nil {
		// If there was an error while upgrading the HTTP connection to a WebSocket connection return a relevant error
		http.Error(serverHTTPResponse, "Unable to upgrade HTTP connection to a WebSocket connection", 400)
		return
	}

	// Require successful authentication before allowing a client to send a message
	_, websocketConnectionStateErr := requireAuth(websocketConnection)
	if websocketConnectionStateErr != nil {
		// If the authentication failed, terminate the websocket connection to the client
		log.Println("Authentication Failed:", websocketConnectionStateErr)
		websocketConnection.WriteMessage(websocket.BinaryMessage, []byte(websocketConnectionStateErr.Error()))
		log.Println("Terminating websocket connection to client.")
		return
	}

	// Notify the client that authentication succeeded
	websocketConnection.WriteMessage(websocket.BinaryMessage, []byte("Authentication Succeeded"))

} // func handleWebsocketConnection

func requireAuth(websocketConnection *websocket.Conn) (int, error) {
	// Create a variable to keep track of the websocket connection state
	// Create a byte sequence that we would ask the client to sign
	byteSequenceToSign := []byte("hi")
	// Initialize the Auth protobuf structure
	protobufAuth := backendProtobuf.Auth{}
	// Fill in the byte sequence that we would ask the client to sign
	protobufAuth.ToSign = byteSequenceToSign
	// Prepare the data to be sent to the client
	protobufAuthBytes, protobufAuthBytesErr := proto.Marshal(&protobufAuth)
	if protobufAuthBytesErr != nil {
		// If there is an error while trying to perform protobuf marshaling, terminate the connection
		return websocket.BinaryMessage, protobufAuthBytesErr
	}
	// Send the protobuf data to the client containing the sequence of bytes he needs to sign
	websocketConnection.WriteMessage(websocket.BinaryMessage, protobufAuthBytes)
	// Read the response from the client which should contain his IdenetityPublicKey and the signed byte sequence
	_, clientMessage, readMessageErr := websocketConnection.ReadMessage()
	if readMessageErr != nil {
		// If there is an error while reading the response from the client, terminate the connection
		return websocket.BinaryMessage, readMessageErr
	}
	// Unmarshal the response from the client into our protobuf Auth structure
	protoUnmarshalErr := proto.Unmarshal(clientMessage, &protobufAuth)
	if protoUnmarshalErr != nil {
		// If there is an error while unmarshaling the response from the client, terminate the connection
		return websocket.BinaryMessage, protoUnmarshalErr
	}
	// Create a [32]byte{} identityPublicKey to satisfy ed25519.Verify() type requirements
	identityPublicKey := [32]byte{}
	// Create a [64]byte{} signedByteSequenceFromClient to satisfy ed25519.Verify() type requirements
	signedByteSequenceFromClient := [64]byte{}
	// Decode the hex representation of the identityPublicKey here as transmitting it over the network without hex encoding can cause issues with some clients
	identityPublicKeyDecoded, identityPublicKeyDecodedErr := hex.DecodeString(string(protobufAuth.GetIdentityPublicKey()))
	if identityPublicKeyDecodedErr != nil {
		// If there is an error while decoding the hex identity public key, terminate the connection
		return websocket.BinaryMessage, identityPublicKeyDecodedErr
	}
	// Fill the newly created identityPublicKey with the hex decoded representation of the IdentityPublicKey contained in the response from the client
	copy(identityPublicKey[:], identityPublicKeyDecoded)
	// Fill the newly created signedByteSequenceFromClient with the Signature contained in the response from the client
	copy(signedByteSequenceFromClient[:], protobufAuth.GetSignature())
	// Verify the validity of the signature using ed25519.Verify()
	if ed25519.Verify(&identityPublicKey, byteSequenceToSign, &signedByteSequenceFromClient) {
		// If the signed byte sequence from client has a valid signature, change the websocket connection state and keep the websocket connection alive
		return websocket.BinaryMessage, nil
	}
	// If ed25519.Verify() failed to verify the signature, return a matching reponse
	return websocket.BinaryMessage, errors.New("Invalid Signature")
} // func requireAuth


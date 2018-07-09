package chatbackend

import (
	"net/http"
	"testing"

	"github.com/Bit-Nation/panthalassa/keyManager"
	"github.com/Bit-Nation/panthalassa/keyStore"
	"github.com/Bit-Nation/panthalassa/mnemonic"
	backendProtobuf "github.com/borjantrajanoski/protobuffers"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	require "github.com/stretchr/testify/require"
)

func TestHandleWebsocketConnection(t *testing.T) {
	go StartWebsocketServer()
	// Setup custom headers to allow the Bearer token
	customHeaders := http.Header{}
	// Add the Bearer token to the custom headers
	customHeaders.Add("Bearer", "5d41402abc4b2a76b9719d911017c592")
	// Initialize a websocket dialer
	websocketDialer := websocket.Dialer{}
	// Initialize a websocket connection
	websocketConnection, _, websocketConnectionErr := websocketDialer.Dial("ws://localhost:8080/chat", customHeaders)
	require.Nil(t, websocketConnectionErr)
	// Initialize our protobuf Auth structure
	protobufAuth := backendProtobuf.Auth{}
	// Read the data from the server which should contain the byte sequence we need to sign
	_, serverMessage, readMessageErr := websocketConnection.ReadMessage()
	require.Nil(t, readMessageErr)
	// Unmarshal the data from the server into our protobuf Auth structure
	protoUnmarshalErr := proto.Unmarshal(serverMessage, &protobufAuth)
	require.Nil(t, protoUnmarshalErr)
	// Get the byte sequence that we need to sign
	byteSequenceToSign := protobufAuth.GetToSign()
	// Get a new mnemnoic for a test user Alice
	mnemonicAlice, mnemonicAliceErr := mnemonic.New()
	require.Nil(t, mnemonicAliceErr)
	// Create a new keyStore for Alice using the created mnemnonic
	keyStoreAlice, keystoreAliceErr := keyStore.NewFromMnemonic(mnemonicAlice)
	require.Nil(t, keystoreAliceErr)
	// Create a new keyManager for Alice using the created key store
	keyManagerAlice := keyManager.CreateFromKeyStore(keyStoreAlice)
	// Sign the byte sequence given by the server using Alice's key manager
	signedByteSequence, signedByteSequenceErr := keyManagerAlice.IdentitySign(byteSequenceToSign)
	require.Nil(t, signedByteSequenceErr)
	// Get Alice's hex encoded identity public key
	identityPublicKeyAliceHex, identityPublicKeyAliceHexErr := keyManagerAlice.IdentityPublicKey()
	require.Nil(t, identityPublicKeyAliceHexErr)
	// Set Alice's hex encoded identity public key in our protobuf Auth structure so we can send it to the server
	protobufAuth.IdentityPublicKey = []byte(identityPublicKeyAliceHex)
	// Set Alice's signed byte sequence as a signature in our protobuf Auth structure so we can send it to the server
	protobufAuth.Signature = signedByteSequence
	// Marshal our protobuf Auth structure so that we can send it via our websocket connection
	protobufAuthBytes, protobufAuthBytesErr := proto.Marshal(&protobufAuth)
	require.Nil(t, protobufAuthBytesErr)
	// Send our protobuf Auth structure via our websocket connection
	websocketConnection.WriteMessage(websocket.BinaryMessage, protobufAuthBytes)
	// Get the server response in regards to our Auth attempt
	_, authenticationResult, readMessageErr := websocketConnection.ReadMessage()
	require.Nil(t, readMessageErr)
	// If it's successfull we can continue to send messages
	require.Equal(t, "Authentication Succeeded", string(authenticationResult))

}


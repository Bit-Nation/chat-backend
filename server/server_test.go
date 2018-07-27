package chatbackend

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"

	"github.com/Bit-Nation/panthalassa/keyManager"
	"github.com/Bit-Nation/panthalassa/keyStore"
	"github.com/Bit-Nation/panthalassa/mnemonic"
	"github.com/Bit-Nation/panthalassa/profile"
	backendProtobuf "github.com/Bit-Nation/protobuffers"
	"github.com/Bit-Nation/x3dh"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	require "github.com/stretchr/testify/require"
	"github.com/tiabc/doubleratchet"
	"golang.org/x/crypto/ed25519"
)

type Client struct {
	Profile             *profile.Profile
	Mnemonic            mnemonic.Mnemonic
	KeyManager          keyManager.KeyManager
	SignedPreKey        x3dh.KeyPair
	OneTimePreKeys      []x3dh.KeyPair
	WebsocketConnection *websocket.Conn
}

func TestHandleWebsocketConnection(t *testing.T) {
	// Start the websocket server
	go StartWebsocketServer()
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
		"ws://localhost:8080/chat",
		"5d41402abc4b2a76b9719d911017c592",
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
		"ws://localhost:8080/chat",
		"5d41402abc4b2a76b9719d911017c592",
		[]x3dh.KeyPair{},
		x3dh.KeyPair{},
	)
	// Reciever needs to pass authentication
	clientReceiver.testAuth(t)
	// Receiver uploads the one time pre keys
	clientReceiver.testUploadOneTimePreKeys(t)
	// Receiver uploads the signed pre key
	clientReceiver.testUploadSignedPreKey(t)
	// Initial message sender needs to pass authentication
	clientSender.testAuth(t)
	// Initial message sender needs to request the pre key bundle of the receiver
	remotePreKeyBundlePublic := clientSender.testRequestPreKeyBundle(t, []byte("22cfd1af5798544287cbf7721a0a4ebc2506d6f4df05413355a7f5cc86740724"))
	// Initial message sender sends a message to the backend to get persisted
	clientSender.testSendMessage(t, remotePreKeyBundlePublic)
	// We assume Receiver is offline
	clientReceiver.WebsocketConnection.Close()
	// Receiver reconnects
	reconnectedWebsocketConnection := newWebsocketConnection(t, "ws://localhost:8080/chat", "5d41402abc4b2a76b9719d911017c592")
	// We replace the disconnection connection with the re-established websocket connection
	clientReceiver.WebsocketConnection = reconnectedWebsocketConnection
	// Receiver needs to pass auth again
	clientReceiver.testAuth(t)
	// Receiver receives any undelivered messages while he was offline
	unreadChatMessages := clientReceiver.receiveUndeliveredMessages(t)
	// Test if we can decrypt the message successfully
	expectedDecryptedMessages := []string{"SECRETMESSAGENEW1"}
	// For each message that we want to read
	for index, unreadChatMessage := range unreadChatMessages {
		// Try to decrypt them and read them
		clientReceiver.testReadDoubleRatchetMessages(t, unreadChatMessage, expectedDecryptedMessages[index])
	} // for index, unreadChatMessage
} // func TestHandleWebsocketConnection

func newStaticSignedPreKeyReceiver() x3dh.KeyPair {
	// Static SignedPreKey to make it easier for testing
	signedPreKeyReceiver := x3dh.KeyPair{}
	signedPreKeyReceiver.PublicKey = [32]byte{224, 145, 192, 31, 248, 20, 4, 238, 131, 116, 219, 3, 105, 218, 251, 88, 136, 64, 31, 86, 188, 112, 29, 15, 255, 88, 111, 51, 47, 155, 0, 73}
	signedPreKeyReceiver.PrivateKey = [32]byte{72, 26, 177, 188, 146, 165, 221, 228, 180, 107, 65, 34, 68, 102, 103, 219, 49, 123, 99, 163, 73, 2, 163, 64, 37, 243, 197, 12, 230, 18, 110, 86}
	return signedPreKeyReceiver
}

func newStaticOneTimePreKeysReceiver() []x3dh.KeyPair {
	// Static OneTimePreKey to make it easier for testing
	oneTimePreKeyReceiver := x3dh.KeyPair{}
	oneTimePreKeyReceiver.PublicKey = [32]byte{152, 92, 130, 237, 124, 95, 40, 165, 218, 47, 160, 237, 178, 113, 53, 115, 166, 209, 228, 195, 23, 218, 116, 73, 84, 3, 74, 34, 215, 150, 216, 78}
	oneTimePreKeyReceiver.PrivateKey = [32]byte{224, 29, 132, 210, 252, 220, 252, 165, 131, 176, 96, 173, 180, 208, 196, 171, 229, 56, 241, 237, 59, 86, 164, 13, 253, 102, 55, 158, 168, 123, 81, 101}
	return []x3dh.KeyPair{oneTimePreKeyReceiver}
}

func newWebsocketConnection(t *testing.T, websocketURL, bearer string) *websocket.Conn {
	// Setup custom headers to allow the Bearer token
	customHeaders := http.Header{}
	// Add the Bearer token to the custom headers
	customHeaders.Add("Bearer", bearer)
	// Initialize a websocket dialer
	websocketDialer := websocket.Dialer{}
	// Initialize a websocket connection of a message sender
	websocketConnection, _, websocketConnectionErr := websocketDialer.Dial(websocketURL, customHeaders)
	require.Nil(t, websocketConnectionErr)
	return websocketConnection
}
func newClient(t *testing.T, name, location, image, mnemonicString, websocketURL, bearer string, oneTimePreKeys []x3dh.KeyPair, signedPreKey x3dh.KeyPair) Client {
	// Establish a new websocket connection
	websocketConnection := newWebsocketConnection(t, websocketURL, bearer)
	// Use the mnemonic string supplied
	mnemonic, mnemonicErr := mnemonic.FromString(mnemonicString)
	require.Nil(t, mnemonicErr)
	// Create a new keystore from the mnemonic
	keyStore, keystoreErr := keyStore.NewFromMnemonic(mnemonic)
	require.Nil(t, keystoreErr)
	// Create a new keymanager using the keyStore
	keyManager := keyManager.CreateFromKeyStore(keyStore)
	// Create a signed version of the profile
	profileSigned, profileErr := profile.SignProfile(name, location, image, *keyManager)
	require.Nil(t, profileErr)
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
	// Set the WebsocketCOnnection
	client.WebsocketConnection = websocketConnection
	// Return a client object containing all of the set values
	return client
} // func newClient

func (c *Client) testUploadOneTimePreKeys(t *testing.T) {
	// Initialize our Message structure to send a request to the backend
	messageToBackendProtobuf := backendProtobuf.BackendMessage{}
	// Initialize an empty Response structure
	messageToBackendProtobuf.Response = &backendProtobuf.BackendMessage_Response{}
	// For each oneTimePreKey
	for _, oneTimePreKey := range c.OneTimePreKeys {
		// Initialize an empty PreKey structure
		preKeyProtobuf := backendProtobuf.PreKey{}
		// Set the Key field in the PreKey structure to the PublicKey from the oneTimePreKey x3dh.KeyPair
		preKeyProtobuf.Key = oneTimePreKey.PublicKey[:]
		// Set the IdentityKey in PreKey structure to the IdentityPubKey in the Client profile
		preKeyProtobuf.IdentityKey = c.Profile.Information.IdentityPubKey
		// Sign the IdentityKey with the KeyManager of the client
		identityKeySignature, identityKeySignatureErr := c.KeyManager.IdentitySign(preKeyProtobuf.IdentityKey)
		require.Nil(t, identityKeySignatureErr)
		// Set the IdentityKeySignature in the PreKey structure to the resulting signature of the IdentitySign process
		preKeyProtobuf.IdentityKeySignature = identityKeySignature
		// Append the PreKey structure to the message response we are about to send to the backend
		messageToBackendProtobuf.Response.OneTimePrekeys = append(messageToBackendProtobuf.Response.OneTimePrekeys, &preKeyProtobuf)
	} // for _, oneTimePreKey := range c.OneTimePreKeys
	// Use protobuf to marshal the message response we are about to send
	messageToBackendProtobufBytes, messageToBackendProtobufBytesErr := proto.Marshal(&messageToBackendProtobuf)
	require.Nil(t, messageToBackendProtobufBytesErr)
	// Send the message over the websocket connection
	writeMessageError := c.WebsocketConnection.WriteMessage(websocket.BinaryMessage, messageToBackendProtobufBytes)
	require.Nil(t, writeMessageError)
	for _, oneTimePreKey := range messageToBackendProtobuf.Response.OneTimePrekeys {
		// Read the response from the backend
		_, messageFromBackendProtobufBytes, readMessageErr := c.WebsocketConnection.ReadMessage()
		require.Nil(t, readMessageErr)
		// Marshal the one time pre key so that we can compare it with the backend response
		oneTimePreKeyBytes, protoMarshalErr := proto.Marshal(oneTimePreKey)
		require.Nil(t, protoMarshalErr)
		// Make sure the backend echoes back the oneTimePreKey we sent to confirm that the OneTimePreKeys were persisted
		require.Equal(t, messageFromBackendProtobufBytes, oneTimePreKeyBytes)
	} // for _, oneTimePreKey
} // testSendOneTimePreKeys

func (c *Client) testUploadSignedPreKey(t *testing.T) {
	// Initialize our Message structure to send a request to the backend
	messageToBackendProtobuf := backendProtobuf.BackendMessage{}
	// Initialize an empty Response structure
	messageToBackendProtobuf.Response = &backendProtobuf.BackendMessage_Response{}
	// Initialize an empty PreKey structure
	preKeyProtobuf := backendProtobuf.PreKey{}
	// Set the Key field in the PreKey structure to the PublicKey from the signedPreKey x3dh.KeyPair
	preKeyProtobuf.Key = c.SignedPreKey.PublicKey[:]
	// Set the IdentityKey in PreKey structure to the IdentityPubKey in the Client profile
	preKeyProtobuf.IdentityKey = c.Profile.Information.IdentityPubKey
	// Sign the IdentityKey with the KeyManager of the client
	identityKeySignature, identityKeySignatureErr := c.KeyManager.IdentitySign(preKeyProtobuf.IdentityKey)
	require.Nil(t, identityKeySignatureErr)
	// Set the IdentityKeySignature in the PreKey structure to the resulting signature of the IdentitySign process
	preKeyProtobuf.IdentityKeySignature = identityKeySignature
	// Append the PreKey structure to the message response we are about to send to the backend
	messageToBackendProtobuf.Response.SignedPreKey = &preKeyProtobuf
	// Use protobuf to marshal the message response we are about to send
	messageToBackendProtobufBytes, messageToBackendProtobufBytesErr := proto.Marshal(&messageToBackendProtobuf)
	require.Nil(t, messageToBackendProtobufBytesErr)
	// Send the message over the websocket connection
	writeMessageError := c.WebsocketConnection.WriteMessage(websocket.BinaryMessage, messageToBackendProtobufBytes)
	require.Nil(t, writeMessageError)
	// Read the response from the backend
	_, messageFromBackendProtobufBytes, readMessageErr := c.WebsocketConnection.ReadMessage()
	require.Nil(t, readMessageErr)
	// Marhsal the signedPreKey so that we can compare it with the backend response
	signedPreKeyBytes, protoMarshalErr := proto.Marshal(&preKeyProtobuf)
	require.Nil(t, protoMarshalErr)
	// Make sure the backend echoes back the signedPreKey we sent to confirm that the signedPreKey was persisted
	require.Equal(t, messageFromBackendProtobufBytes, signedPreKeyBytes)
} // testSendOneTimePreKeys

func (c *Client) testSendMessage(t *testing.T, receiverPreKeyBundlePublic PreKeyBundlePublic) {
	// Initialize our Message structure to send a request to the backend
	messageToBackendProto := backendProtobuf.BackendMessage{}
	// Initialize an empty Request structure
	messageToBackendProto.Request = &backendProtobuf.BackendMessage_Request{}
	// Create a key store for the message Sender using the mnemonic from the client
	keyStoreSender, keystoreSenderErr := keyStore.NewFromMnemonic(c.Mnemonic)
	require.Nil(t, keystoreSenderErr)
	// Create a new keyManager for the message Sender using the created key store
	keyManagerSender := keyManager.CreateFromKeyStore(keyStoreSender)
	// Get the message Sender chat id key pair
	chatIDKeyPairSender, chatIDKeyPairErr := keyManagerSender.ChatIdKeyPair()
	require.Nil(t, chatIDKeyPairErr)
	// Get the message Sender identity public key
	identityPublicKeySenderHex, identityPublicKeySenderHexErr := keyManagerSender.IdentityPublicKey()
	require.Nil(t, identityPublicKeySenderHexErr)
	// Create a new 25519 curve for the message Sender
	curveSender := x3dh.NewCurve25519(rand.Reader)
	// Create a new x3dh for Sender using the 25519 curve and the message Sender chat id key pair
	x3dhSender := x3dh.New(&curveSender, sha256.New(), "testing", chatIDKeyPairSender)
	// Initialize xh3d protocol from the Sender side
	initializedX3DHProtocolSender, initializedX3DHProtocolErr := x3dhSender.CalculateSecret(&receiverPreKeyBundlePublic)
	require.Nil(t, initializedX3DHProtocolErr)
	// Use the calculated shared secret which is a result from consuming the message Receiver's prekey bundle
	sharedSecretSender := initializedX3DHProtocolSender.SharedSecret
	// Initialize a new double Ratchet session for Sender which would allow her to encrypt a message
	doubleRatchetSessionSender, doubleRatchetSessionErr := doubleratchet.New(sharedSecretSender, doubleratchetKeyPair{keyPair: chatIDKeyPairSender}, doubleratchet.WithKeysStorage(&doubleratchet.KeysStorageInMemory{}))
	require.Nil(t, doubleRatchetSessionErr)
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
	require.Nil(t, senderEphemeralKeySignatureErr)
	// Set the EphemeralKeySignature to the signature obtained from the IdentitySign method
	chatMessageSender.EphemeralKeySignature = senderEphemeralKeySignature
	// Set the Message to the doube Ratchet message
	chatMessageSender.Message = &protobufDoubleRatchetMsgSender
	// Set the message receiver to message Receiver IdentityKey from his PreKeyBundle
	// @TODO : encode to hex?
	chatMessageSender.Receiver = []byte(receiverPreKeyBundlePublic.BundleIdentityKey)
	// Set the message sender to the message Sender IdentityKey
	chatMessageSender.Sender = []byte(identityPublicKeySenderHex)
	// Set the message ID
	chatMessageSender.MessageID = []byte("@TODO")
	// Set the used shared secret, (not in plain form)
	chatMessageSender.UsedSharedSecret = []byte("@TODO")
	// Set the version
	// @TODO : setup proper versioning?
	chatMessageSender.Version = 1
	// Append the message to the slice of messages in our request
	messageToBackendProto.Request.Messages = append(messageToBackendProto.Request.Messages, &chatMessageSender)
	// Marshal our protobuf ChatMessage structure so that we can send it via our websocket connection
	messageToBackendProtoBytes, messageToBackendProtoBytesErr := proto.Marshal(&messageToBackendProto)
	require.Nil(t, messageToBackendProtoBytesErr)
	// Send our protobuf ChatMessage structure via our websocket connection
	writeMessageError := c.WebsocketConnection.WriteMessage(websocket.BinaryMessage, messageToBackendProtoBytes)
	require.Nil(t, writeMessageError)
	// For each message that we are sending to the backend
	for _, singleMessageToBackendProtobuf := range messageToBackendProto.Request.Messages {
		// Marshal each message in protobuf bytes
		messageToBackendProtobufBytes, singleMessageToBackendProtobufBytesErr := proto.Marshal(singleMessageToBackendProtobuf)
		require.Nil(t, singleMessageToBackendProtobufBytesErr)
		// Read the response from the backend
		_, messageFromBackendProtobufBytes, readMessageErr := c.WebsocketConnection.ReadMessage()
		require.Nil(t, readMessageErr)
		// Make sure the backend echoes back the messages we sent to confirm that the messages was persisted
		require.Equal(t, messageFromBackendProtobufBytes, messageToBackendProtobufBytes)
	} // for _, singleMessageToBackendProtobuf := range messageToBackendProto.Request.Messages
} // func (c *Client) testSendMessage

func (c *Client) testRequestPreKeyBundle(t *testing.T, preKeyBundleIdentifier []byte) PreKeyBundlePublic {
	// Initialize our Message structure to send a request to the backend
	messageToBackendProto := backendProtobuf.BackendMessage{}
	// Initialize an empty Request structure
	messageToBackendProto.Request = &backendProtobuf.BackendMessage_Request{}
	// Fill in the key of the client we want to requirest a pre key bundle for so that we can chat with
	messageToBackendProto.Request.PreKeyBundle = preKeyBundleIdentifier
	// Protobuf marshal our message structure so that we can send it over our websocket connection.
	messageToBackendProtoBytes, messageToBackendProtoErr := proto.Marshal(&messageToBackendProto)
	require.Nil(t, messageToBackendProtoErr)
	// Send our pre key bundle request to the backend
	writeMessageErr := c.WebsocketConnection.WriteMessage(websocket.BinaryMessage, messageToBackendProtoBytes)
	require.Nil(t, writeMessageErr)
	// Read the response from the backend
	_, messageFromBackend, readMessageErr := c.WebsocketConnection.ReadMessage()
	require.Nil(t, readMessageErr)
	// Create a structure that would hold the unmarshaled protobuf response from the backend
	var messageFromBackendProtobuf backendProtobuf.BackendMessage
	// Unmarshal the protobuf response from the backend
	protoUnmarshalErr := proto.Unmarshal(messageFromBackend, &messageFromBackendProtobuf)
	require.Nil(t, protoUnmarshalErr)
	// Get the Response from the received message
	responseFromBackend := messageFromBackendProtobuf.Response
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
	identityPublicKeyFromBackendHex := hex.EncodeToString(identityPublicKeyFromBackend)
	// Make sure that the hex encoded identity public key we used to make the initial request is the same as the one returned by the backend
	require.Equal(t, string(preKeyBundleIdentifier), identityPublicKeyFromBackendHex)
	// Create a public pre key bundle structure
	requrestedPreKeyBundle := PreKeyBundlePublic{}
	// Set the pre key bundle IdentityKey
	requrestedPreKeyBundle.BundleIdentityKey = identityPublicKeyFromBackendHex
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
	require.Nil(t, chatIDKeyPairErr)
	// Create a new 25519 curve for message Receiver
	curveReceiver := x3dh.NewCurve25519(rand.Reader)
	// Create a new x3dh for the message Receiver using the 25519 curve and the message Receiver's chat id key pair
	x3dhReceiver := x3dh.New(&curveReceiver, sha256.New(), "testing", chatIDKeyPairReceiver)
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
	// Create a remoteChatIDKey variable to conform to the x3dh.PublicKey type requirement
	var remoteChatIDKey x3dh.PublicKey
	// Create a remoteEphemeralKey variable to conform to the x3dh.PublicKey type requirement
	var remoteEphemeralKey x3dh.PublicKey
	// Copy the bytes from the doubleRatchetMsgAlice.Header.DH to remoteChatIDKey
	copy(remoteChatIDKey[:], unreadChatMessage.Message.DoubleRatchetPK[:])
	// Copy the bytes from the EphemeralKey supplied in the protobuf chat message to remoteEphemeralKey
	copy(remoteEphemeralKey[:], unreadChatMessage.EphemeralKey[:])
	// Initialize an x3dh protocol using the ChatIDKey and EphemeralKey from the message Sender and the private OneTimePreKey and SignedPreKey parts from the message receiver
	customProtocolInitialization := x3dh.ProtocolInitialisation{
		RemoteIdKey:        remoteChatIDKey,
		RemoteEphemeralKey: remoteEphemeralKey,
		MyOneTimePreKey:    &receiverPreKeyBundlePrivate.OneTimePreKey,
		MySignedPreKey:     receiverPreKeyBundlePrivate.SignedPreKey,
	}
	// Derive the shared secret from the custom initialised x3dh protocol
	sharedSecretReceiver, sharedSecretErr := x3dhReceiver.SecretFromRemote(customProtocolInitialization)
	require.Nil(t, sharedSecretErr)
	// Create a remoteChatIDKeyBytes variable to conform to the [32]byte type requirement and set it to the value of remoteChatIDKey
	var remoteChatIDKeyBytes [32]byte = remoteChatIDKey
	// Initiate a new double retchet session using the derived shared secret and the remoteChatIDKey
	doubleRatchetSessionReceiver, doubleRatchetSessionErr := doubleratchet.NewWithRemoteKey(sharedSecretReceiver, remoteChatIDKeyBytes, doubleratchet.WithKeysStorage(&doubleratchet.KeysStorageInMemory{}))
	require.Nil(t, doubleRatchetSessionErr)
	// Create a doubleRatchetKey variable to conform to the doubleratchet.Key type requirement
	var doubleRatchetKey doubleratchet.Key
	// Copy the bytes from remoteChatIDKey to the doubleRatchetKey
	copy(doubleRatchetKey[:], remoteChatIDKey[:])
	// Create a doubleRatchetHeader structure
	doubleRatchetHeader := doubleratchet.MessageHeader{}
	// Set the sender's current ratchet public key
	doubleRatchetHeader.DH = doubleRatchetKey
	// Set the number of the message in the sending chain
	doubleRatchetHeader.N = unreadChatMessage.Message.N
	// Set the length of the previous sending chain.
	doubleRatchetHeader.PN = unreadChatMessage.Message.Pn
	// Create a doubleRatchetMessage structure
	doubleRatchetMessage := doubleratchet.Message{}
	// Set the doubleRatchetMessage Header
	doubleRatchetMessage.Header = doubleRatchetHeader
	// Set the doubleRatchetMessage CipherText which is the encrypted double rateched message that we want to decrypt
	doubleRatchetMessage.Ciphertext = unreadChatMessage.Message.CipherText
	// Decrypt the doubleRatchetMessage using the previously initialized doubleRatchetSession from the message receiver
	decryptedMessageFromAlice, decryptedMessageFromAliceErr := doubleRatchetSessionReceiver.RatchetDecrypt(doubleRatchetMessage, []byte{})
	require.Nil(t, decryptedMessageFromAliceErr)
	// Make sure that the decrypted message matches the original message
	require.Equal(t, expectedDecryptedMessage, string(decryptedMessageFromAlice))

} // testReadDoubleRatchetMessages

func (c *Client) receiveUndeliveredMessages(t *testing.T) []*backendProtobuf.ChatMessage {
	// Read the message from backend
	_, undeliveredMessages, readMessageErr := c.WebsocketConnection.ReadMessage()
	require.Nil(t, readMessageErr)
	// Create an empty BackendMessage structure
	messageFromBackendProto := backendProtobuf.BackendMessage{}
	// Unmarshal the undeliveredMessagesd into our backend message structure
	protoUnmarshalErr := proto.Unmarshal(undeliveredMessages, &messageFromBackendProto)
	require.Nil(t, protoUnmarshalErr)
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
	// Set the type of request we are replying to
	messageToBackend.RequestID = "@TODO"
	// Read the data from the server which should contain the byte sequence we need to sign
	_, messageFromBackendBytes, readMessageErr := c.WebsocketConnection.ReadMessage()
	require.Nil(t, readMessageErr)
	// Unmarshal the data from the server into our Message structure
	protoUnmarshalErr := proto.Unmarshal(messageFromBackendBytes, &messageFromBackend)
	require.Nil(t, protoUnmarshalErr)
	// Create a byte slice to store our random bytes
	clientRandomBytes := make([]byte, 4)
	// Read random bytes into our slice
	_, randomBytesErr := rand.Read(clientRandomBytes)
	require.Nil(t, randomBytesErr)
	// Get the byte sequence that we need to sign
	byteSequenceToSign := messageFromBackend.Request.Auth.ToSign
	// Make sure that backend sends us exactly 4 bytes to avoid signing something potentially malicious
	require.Equal(t, 4, len(byteSequenceToSign))
	// Append our own 4 random bytes to prevent backend abuse
	byteSequenceToSign = append(byteSequenceToSign, clientRandomBytes...)
	// Make sure that we are about to sign exactly 8 bytes
	require.Equal(t, 8, len(byteSequenceToSign))
	// Create a new keyStore for Client using the created mnemnonic
	keyStoreClient, keystoreClientErr := keyStore.NewFromMnemonic(c.Mnemonic)
	require.Nil(t, keystoreClientErr)
	// Create a new keyManager for Client using the created key store
	keyManagerClient := keyManager.CreateFromKeyStore(keyStoreClient)
	// Sign the byte sequence given by the server using Client's key manager
	signedByteSequence, signedByteSequenceErr := keyManagerClient.IdentitySign(byteSequenceToSign)
	require.Nil(t, signedByteSequenceErr)
	// Get Client's hex encoded identity public key
	identityPublicKeyClientHex, identityPublicKeyClientHexErr := keyManagerClient.IdentityPublicKey()
	require.Nil(t, identityPublicKeyClientHexErr)
	// Represent Client's hex encoded identity public key as bytes
	identityPublicKeyClientBytes := []byte(identityPublicKeyClientHex)
	// Set the bytes prespresentation of Client's hex encoded identity public key in our protobuf Auth structure so we can send it to the server
	messageToBackend.Response.Auth.IdentityPublicKey = identityPublicKeyClientBytes
	// Set Client's 8 byte sequence which was signed in our protobuf Auth structure so we can send it to the server
	messageToBackend.Response.Auth.ToSign = byteSequenceToSign
	// Set Client's signed byte sequence as a signature in our protobuf Auth structure so we can send it to the server
	messageToBackend.Response.Auth.Signature = signedByteSequence
	// Marshal our protobuf Auth structure so that we can send it via our websocket connection
	messageToBackendBytes, protobufAuthBytesErr := proto.Marshal(&messageToBackend)
	require.Nil(t, protobufAuthBytesErr)
	// Send our protobuf Auth structure via our websocket connection
	writeMessageErr := c.WebsocketConnection.WriteMessage(websocket.BinaryMessage, messageToBackendBytes)
	require.Nil(t, writeMessageErr)
	// Read back the response from the backend
	_, messageFromBackendBytes, readMessageErr = c.WebsocketConnection.ReadMessage()
	require.Nil(t, readMessageErr)
	// Make sure the backend echoes back the authentication attempt as a means to confirm that it's successful
	require.Equal(t, messageToBackendBytes, messageFromBackendBytes)

}

var Reader io.Reader

// Satisfy interface requirements
func Read(b []byte) (n int, err error) {
	return io.ReadFull(Reader, b)
}

// Create doubleratchetKeyPair struct needed to start a custom doubleratchet session
type doubleratchetKeyPair struct {
	keyPair x3dh.KeyPair
}

// Add PrivateKey method to conform to doubleratchet.DHPair interface requrements
func (d doubleratchetKeyPair) PrivateKey() doubleratchet.Key {
	var byt [32]byte = d.keyPair.PrivateKey
	return byt
}

// Add PublicKey method to conform to doubleratchet.DHPair interface requrements
func (d doubleratchetKeyPair) PublicKey() doubleratchet.Key {
	var byt [32]byte = d.keyPair.PublicKey
	return byt
}

type PreKeyBundlePublic struct {
	BundleChatIdentityKey x3dh.PublicKey
	BundleSignedPreKey    x3dh.PublicKey
	BundleOneTimePreKey   x3dh.PublicKey
	BundleIdentityKey     string
	BundleSignature       [64]byte
}

type PreKeyBundlePrivate struct {
	OneTimePreKey x3dh.PrivateKey
	SignedPreKey  x3dh.PrivateKey
}

func (b *PreKeyBundlePublic) IdentityKey() x3dh.PublicKey {
	return b.BundleChatIdentityKey
}

func (b *PreKeyBundlePublic) SignedPreKey() x3dh.PublicKey {
	return b.BundleSignedPreKey
}

func (b *PreKeyBundlePublic) OneTimePreKey() *x3dh.PublicKey {
	return &b.BundleOneTimePreKey
}

func (b *PreKeyBundlePublic) ValidSignature() bool {
	// @TODO REMOVE RETURN TRUE AND CALCULATE SIGNATURE IN ANOTHER WAY
	return true
	rawIDKey, err := hex.DecodeString(b.BundleIdentityKey)
	if err != nil {
		return false
	}
	return ed25519.Verify(rawIDKey[:], b.hashBundle(), b.BundleSignature[:])
}

// sign profile with given private key
func (b *PreKeyBundlePublic) Sign(km keyManager.KeyManager) error {
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

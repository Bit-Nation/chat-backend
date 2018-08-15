package chatbackend

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log/syslog"
	"os"

	firestore "cloud.google.com/go/firestore"
	firebase "firebase.google.com/go"
	backendProtobuf "github.com/Bit-Nation/protobuffers"
	golangProto "github.com/golang/protobuf/proto"
	gorillaWebSocket "github.com/gorilla/websocket"
	option "google.golang.org/api/option"
)

// Use interface for storage to make it easily swappable
type storageInterface interface {
	persistChatMessagesFromClient([]*backendProtobuf.ChatMessage) error
	persistOneTimePreKeysFromClient([]*backendProtobuf.PreKey) error
	persistSignedPreKeyFromClient(*backendProtobuf.PreKey) error
	deleteFieldFromStorage(string, string) error
	getClientDataFromStorage() (*authenticatedClientFirestore, error)
}

type authenticatedClientFirestore struct {
	authenticatedIdentityPublicKeyHex string
	firestoreConnection               *firestore.Client
	websocketConnection               *gorillaWebSocket.Conn
	encounteredError                  error
	messagesToBeDelivered             [][]byte
	oneTimePreKeys                    [][]byte
	signedPreKey                      []byte
	profile                           []byte
}

func newFirestoreConnection() (*firestore.Client, error) {
	// Initialise an empty context with no values, no deadline, which will never be canceled
	networkContext := context.Background()
	// Get the JSON credentials from our own custom enviroment variable to increase compatibility
	credentialsHex := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS_JSON")
	// Decode the serviceAccount credentials
	credentialsJSON, hexDecodeErr := hex.DecodeString(credentialsHex)
	if hexDecodeErr != nil {
		return nil, hexDecodeErr
	} // if hexDecodeErr !- nil {
	// Create a service account file so we can use firestore helper functions to authenticate properly
	serviceAccountFile, serviceAccountFileErr := ioutil.TempFile(os.TempDir(), "serviceAccount_")
	if serviceAccountFileErr != nil {
		return nil, serviceAccountFileErr
	} // if serviceAccountFileErr != nil
	// Store the full path and name of the serviceAccount temp file to avoid calling .Name() twice
	serviceAccountFileName := serviceAccountFile.Name()
	// Make sure to delete the temporariy file
	defer os.Remove(serviceAccountFileName)
	// Write the serviceAccount json information into the serviceAccount temp file
	if _, writeErr := serviceAccountFile.WriteString(string(credentialsJSON)); writeErr != nil {
		return nil, writeErr
	} // if _, writeErr
	// Use the serviceAccount temp file as a source of a credentials file
	serviceAccount := option.WithCredentialsFile(serviceAccountFileName)
	// Create a new firebase app based using the serviceAccount temp file
	firebaseApp, firebaseAppErr := firebase.NewApp(networkContext, nil, serviceAccount)
	if firebaseAppErr != nil {
		return nil, firebaseAppErr
	} // if firebaseAppErr != nil
	// Initialise the firestore
	firestoreClient, firestoreError := firebaseApp.Firestore(networkContext)
	if firestoreError != nil {
		return nil, firestoreError
	} // if firestoreError != nil
	// Make sure to close the firestore once the function returns
	return firestoreClient, nil
} // func newFirestoreConnection

func getProfileFromStorage(identityPublicKeyHex string) ([]byte, error) {
	// Create a new connection to the firestore storage service
	firestoreConnection, firestoreConnectionErr := newFirestoreConnection()
	if firestoreConnectionErr != nil {
		return nil, firestoreConnectionErr
	} // if firestoreClientErr != nil
	// Initialise an empty context with no values, no deadline, which will never be canceled
	networkContext := context.Background()
	// Get a snapshot of the document that contains the data we are interested in
	documentSnapshot, documentSnapshotErr := firestoreConnection.Collection("clients").Doc(identityPublicKeyHex).Get(networkContext)
	// If there is an error fetching the document
	if documentSnapshotErr != nil {
		// Log the error but don't return it as it may leak non-sensitive data that it's better not to be leaked
		logError(syslog.LOG_ERR, documentSnapshotErr)
		return nil, errors.New("Profile not found")
	} // if documentSnapshotErr != nil
	// Retreive the data from the document snapshot into a map[string]interface{}
	clientDataMap := documentSnapshot.Data()
	// If the client profile exists in the storage
	if singleUserProfileBase64, exists := clientDataMap["profile"]; exists {
		// Base64 decode the it to get the protobuf bytes
		singleUserProfile, singleUserProfileErr := base64.StdEncoding.DecodeString(singleUserProfileBase64.(string))
		// If there is an error with the base64 decoding, return the error
		if singleUserProfileErr != nil {
			return nil, singleUserProfileErr
		} // if singleUserProfileErr
		return singleUserProfile, nil
	} // if singleUserProfileBase64, exists
	return nil, errors.New("Profile not found")
}

func persistProfileToStorage(identityPublicKeyHex string, profileBase64 string) error {
	// Create a new connection to the firestore storage service
	firestoreConnection, firestoreConnectionErr := newFirestoreConnection()
	if firestoreConnectionErr != nil {
		return firestoreConnectionErr
	} // if firestoreConnectionErr != nil
	// Persist the client profile
	_, firestoreWriteDataErr := firestoreConnection.Collection("clients").Doc(identityPublicKeyHex).Set(context.Background(), map[string]interface{}{
		"profile": profileBase64,
	}, firestore.MergeAll)
	if firestoreWriteDataErr != nil {
		return firestoreWriteDataErr
	} // if firestoreWriteDataErr != nil
	return nil
} // func persistProfileToStorage

func (a *authenticatedClientFirestore) getClientDataFromStorage() (*authenticatedClientFirestore, error) {
	// Create a new connection to the firestore storage service
	firestoreClient, firestoreClientErr := newFirestoreConnection()
	if firestoreClientErr != nil {
		return a, firestoreClientErr
	} // if firestoreClientErr != nil
	a.firestoreConnection = firestoreClient
	// Initialise an empty context with no values, no deadline, which will never be canceled
	networkContext := context.Background()
	// Make sure a document exists on the storage for the client that is requesting it, if it exists, it wont get overwritten, if it doesn't it will be created
	a.firestoreConnection.Collection("clients").Doc(a.authenticatedIdentityPublicKeyHex).Set(networkContext, map[string]interface{}{"OK": 1}, firestore.MergeAll)
	// Get a snapshot of the document that contains the data we are interested in
	documentSnapshot, documentSnapshotErr := a.firestoreConnection.Collection("clients").Doc(a.authenticatedIdentityPublicKeyHex).Get(networkContext)
	if documentSnapshotErr != nil {
		return a, documentSnapshotErr
	} // if documentSnapshotErr != nil
	// Retreive the data from the document snapshot into a map[string]interface{}
	clientDataMap := documentSnapshot.Data()
	// If the client profile exists in the storage
	if singleUserProfileBase64, exists := clientDataMap["profile"]; exists {
		// Base64 decode the it to get the protobuf bytes
		singleUserProfile, singleUserProfileErr := base64.StdEncoding.DecodeString(singleUserProfileBase64.(string))
		// If there is an error with the base64 decoding, return the error
		if singleUserProfileErr != nil {
			return a, singleUserProfileErr
		} // if singleUserProfileErr
		a.profile = singleUserProfile
	} // if singleUserProfileBase64, exists
	if singleUserSignedPreKeyBase64, exists := clientDataMap["signedPreKey"]; exists {
		// Base64 decode the it to get the protobuf bytes
		singleUserSignedPreKey, singleUserSignedPreKeyErr := base64.StdEncoding.DecodeString(singleUserSignedPreKeyBase64.(string))
		// If there is an error with the base64 decoding, fill in the error field in the message to client with the error that occured
		if singleUserSignedPreKeyErr != nil {
			return a, singleUserSignedPreKeyErr
		} // if singleUserProfileErr
		a.signedPreKey = singleUserSignedPreKey
	} // if singleUserSignedPreKeyBase64, exists
	// @TODO check if the amount of oneTimePreKeys is sufficient
	// If there there are oneTimePreKeys in the storage storage
	if singleUserOneTimePreKeys, exists := clientDataMap["oneTimePreKeys"]; exists {
		// Cast the whole interface{} into a map[string]interface{} as per data firestore spec
		singleUserOneTimePreKeysMap := singleUserOneTimePreKeys.(map[string]interface{})
		// As long as we have at least one oneTimePreKey
		for _, singleUserOneTimePreKeyBase64 := range singleUserOneTimePreKeysMap {
			// Base64 decode the it to get the protobuf bytes
			singleUserOneTimePreKey, singleUserOneTimePreKeyErr := base64.StdEncoding.DecodeString(singleUserOneTimePreKeyBase64.(string))
			// If there is an error with the base64 decoding, return the error
			if singleUserOneTimePreKeyErr != nil {
				return a, singleUserOneTimePreKeyErr
			} // if singleUserProfileErr
			a.oneTimePreKeys = append(a.oneTimePreKeys, singleUserOneTimePreKey)
		} // for singleUserOneTimePreKeyIndex, singleUserOneTimePreKey
	} // if singleUserSignedPreKeyBase64, exists
	// If there are undelivered messages in the storage
	if singleUserChatMessages, exists := clientDataMap["chatMessages"]; exists {
		// Cast the whole interface{} into a map[string]interface{} as per data firestore spec
		singleUserChatMessagesMap := singleUserChatMessages.(map[string]interface{})
		// As long as we have at least one chatMessage
		for _, singleUserChatMessageBase64 := range singleUserChatMessagesMap {
			// Base64 decode the it to get the protobuf bytes
			singleUserChatMessage, singleUserChatMessageErr := base64.StdEncoding.DecodeString(singleUserChatMessageBase64.(string))
			// If there is an error with the base64 decoding, return the error
			if singleUserChatMessageErr != nil {
				return a, singleUserChatMessageErr
			} // if singleUserProfileErr
			// Append each chat message into the messagesToBeDelivered [][]byte slice
			a.messagesToBeDelivered = append(a.messagesToBeDelivered, singleUserChatMessage)
		} // for singleUserOneTimePreKeyIndex, singleUserOneTimePreKey
	} // if singleUserSignedPreKeyBase64, exists
	return a, nil
} // func getClientDataFromDatastore


func (a *authenticatedClientFirestore) persistChatMessagesFromClient(messagesFromClient []*backendProtobuf.ChatMessage) error {
	// For each message received from client
	for _, singleMessageFromClient := range messagesFromClient {
		// Use protobuf to marshal the message into bytes so that we can store it easily
		chatMessageProtobufBytes, chatMessageProtobufError := golangProto.Marshal(singleMessageFromClient)
		// If there is an error while marshaling the individual message from the client, return it
		if chatMessageProtobufError != nil {
			return chatMessageProtobufError
		} // if chatMessageProtobufError != nil
		// Store the message from the client
		_, firestoreWriteDataErr := a.firestoreConnection.Collection("clients").Doc(hex.EncodeToString(singleMessageFromClient.Receiver)).Set(context.Background(), map[string]interface{}{
			"chatMessages": map[string]interface{}{
				string(singleMessageFromClient.MessageID): base64.StdEncoding.EncodeToString(chatMessageProtobufBytes),
			},
		}, firestore.MergeAll)
		if firestoreWriteDataErr != nil {
			return firestoreWriteDataErr
		} // if firestoreWriteDataErr != nil
	} // for _, singleMessageFromClient
	return nil
} // func (a *authenticatedClientFirestore) persistChatMessages

func (a *authenticatedClientFirestore) persistOneTimePreKeysFromClient(oneTimePreKeysFromClient []*backendProtobuf.PreKey) error {
	// Initialise an empty context with no values, no deadline, which will never be canceled
	networkContext := context.Background()
	// For each one time pre key received from client
	for _, oneTimePreKeyFromClient := range oneTimePreKeysFromClient {
		// Use protobuf to marshal the oneTimePreKey into bytes so that we can store it easily
		oneTimePreKeyFromClientProtobufBytes, protoMarshalErr := golangProto.Marshal(oneTimePreKeyFromClient)
		// If there is an error while marshalling the one time pre key from the client, return it
		if protoMarshalErr != nil {
			return protoMarshalErr
		} // if protoMarshalErr
		// Store the one time pre key from the client
		_, firestoreWriteDataErr := a.firestoreConnection.Collection("clients").Doc(a.authenticatedIdentityPublicKeyHex).Set(networkContext, map[string]interface{}{
			"oneTimePreKeys": map[string]interface{}{
				fmt.Sprint(oneTimePreKeyFromClient.TimeStamp): base64.StdEncoding.EncodeToString(oneTimePreKeyFromClientProtobufBytes),
			},
		}, firestore.MergeAll)
		if firestoreWriteDataErr != nil {
			return firestoreWriteDataErr
		} // if firestoreWriteDataErr != nil
	} // for _, oneTimePreKeyFromClient
	return nil
} // func persistOneTimeKeysFromClient

func (a *authenticatedClientFirestore) persistSignedPreKeyFromClient(signedPreKeyFromClient *backendProtobuf.PreKey) error {
	// Use protobuf to marshal the signed pre key into bytes so that we can store it easily
	signedPreKeyFromClientProtobufBytes, protoMarshalErr := golangProto.Marshal(signedPreKeyFromClient)
	// If there is an error while marshalling the signed pre key from the client, return it
	if protoMarshalErr != nil {
		return protoMarshalErr
	} // if protoMarshalErr
	// Initialise an empty context with no values, no deadline, which will never be canceled
	networkContext := context.Background()
	// Store the SignedPreKey from the client
	_, firestoreWriteDataErr := a.firestoreConnection.Collection("clients").Doc(a.authenticatedIdentityPublicKeyHex).Set(networkContext, map[string]interface{}{
		"signedPreKey": base64.StdEncoding.EncodeToString(signedPreKeyFromClientProtobufBytes),
	}, firestore.MergeAll) // _, firestoreWriteDataErr
	if firestoreWriteDataErr != nil {
		return firestoreWriteDataErr
	} // if firestoreWriteDataErr != nil
	return nil
} // func persistSignedPreKeyFromClient

func (a *authenticatedClientFirestore) deleteFieldFromStorage(field, fieldID string) error {
	// If we have a nested field we will delete it by using an identifier
	if fieldID != "" {
		// This is how we access a nested field in order to delete it specifically without deleting the other keys
		field += "."
	} // if fieldID != ""
	// Delete the field
	_, firestoreWriteDataErr := a.firestoreConnection.Collection("clients").Doc(a.authenticatedIdentityPublicKeyHex).Update(context.Background(), []firestore.Update{
		{
			Path:  field + fieldID,
			Value: firestore.Delete,
		}, // []firestore.Update
	}) // _, firestoreWriteDataErr
	return firestoreWriteDataErr
} // func (a *authenticatedClientFirestore) deleteFieldFromStorage

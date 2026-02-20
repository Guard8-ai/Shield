package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var (
	// ErrMemberNotFound indicates member not found in group.
	ErrMemberNotFound = errors.New("shield: member not found")
	// ErrNoRecipients indicates no recipients for broadcast.
	ErrNoRecipients = errors.New("shield: no recipients")
)

// GroupEncryption provides multi-party group encryption.
type GroupEncryption struct {
	groupKey  [KeySize]byte
	memberKey [KeySize]byte
	memberID  string
	members   map[string][]byte // memberID -> encryptedGroupKey
}

// NewGroupEncryption creates a new group with this member as admin.
func NewGroupEncryption(memberID string, memberKey []byte) (*GroupEncryption, error) {
	if len(memberKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	ge := &GroupEncryption{
		memberID: memberID,
		members:  make(map[string][]byte),
	}
	copy(ge.memberKey[:], memberKey)

	// Generate random group key
	if _, err := rand.Read(ge.groupKey[:]); err != nil {
		return nil, err
	}

	// Encrypt group key for self
	encryptedKey, err := EncryptWithKey(memberKey, ge.groupKey[:])
	if err != nil {
		return nil, err
	}
	ge.members[memberID] = encryptedKey

	return ge, nil
}

// JoinGroup joins an existing group.
func JoinGroup(memberID string, memberKey, encryptedGroupKey []byte) (*GroupEncryption, error) {
	if len(memberKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	ge := &GroupEncryption{
		memberID: memberID,
		members:  make(map[string][]byte),
	}
	copy(ge.memberKey[:], memberKey)

	// Decrypt group key
	groupKey, err := DecryptWithKey(memberKey, encryptedGroupKey, nil)
	if err != nil {
		return nil, err
	}
	copy(ge.groupKey[:], groupKey)
	ge.members[memberID] = encryptedGroupKey

	return ge, nil
}

// AddMember adds a member to the group.
func (ge *GroupEncryption) AddMember(memberID string, memberKey []byte) ([]byte, error) {
	if len(memberKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	// Encrypt group key for new member
	encryptedKey, err := EncryptWithKey(memberKey, ge.groupKey[:])
	if err != nil {
		return nil, err
	}
	ge.members[memberID] = encryptedKey

	return encryptedKey, nil
}

// RemoveMember removes a member (does NOT revoke their key).
func (ge *GroupEncryption) RemoveMember(memberID string) error {
	if _, ok := ge.members[memberID]; !ok {
		return ErrMemberNotFound
	}
	delete(ge.members, memberID)
	return nil
}

// Encrypt encrypts a message for the group.
func (ge *GroupEncryption) Encrypt(plaintext []byte) ([]byte, error) {
	return EncryptWithKey(ge.groupKey[:], plaintext)
}

// Decrypt decrypts a group message.
func (ge *GroupEncryption) Decrypt(ciphertext []byte) ([]byte, error) {
	return DecryptWithKey(ge.groupKey[:], ciphertext, nil)
}

// GroupKey returns the group key (for backup/admin).
func (ge *GroupEncryption) GroupKey() []byte {
	return ge.groupKey[:]
}

// Members returns list of member IDs.
func (ge *GroupEncryption) Members() []string {
	members := make([]string, 0, len(ge.members))
	for id := range ge.members {
		members = append(members, id)
	}
	return members
}

// Fingerprint returns the group key fingerprint.
func (ge *GroupEncryption) Fingerprint() string {
	h := sha256.Sum256(ge.groupKey[:])
	return hex.EncodeToString(h[:8])
}

// BroadcastEncryption provides one-to-many encryption.
type BroadcastEncryption struct {
	senderKey  [KeySize]byte
	recipients map[string][]byte // recipientID -> recipientKey
}

// NewBroadcastEncryption creates a new broadcast sender.
func NewBroadcastEncryption(senderKey []byte) (*BroadcastEncryption, error) {
	if len(senderKey) != KeySize {
		return nil, ErrInvalidKeySize
	}

	be := &BroadcastEncryption{
		recipients: make(map[string][]byte),
	}
	copy(be.senderKey[:], senderKey)

	return be, nil
}

// AddRecipient adds a recipient.
func (be *BroadcastEncryption) AddRecipient(recipientID string, recipientKey []byte) error {
	if len(recipientKey) != KeySize {
		return ErrInvalidKeySize
	}
	keyCopy := make([]byte, KeySize)
	copy(keyCopy, recipientKey)
	be.recipients[recipientID] = keyCopy
	return nil
}

// RemoveRecipient removes a recipient.
func (be *BroadcastEncryption) RemoveRecipient(recipientID string) {
	delete(be.recipients, recipientID)
}

// BroadcastMessage represents a broadcast encrypted message.
type BroadcastMessage struct {
	EncryptedMessage []byte
	RecipientKeys    map[string][]byte // recipientID -> encrypted session key
	SenderProof      []byte
}

// Broadcast encrypts a message for all recipients.
func (be *BroadcastEncryption) Broadcast(plaintext []byte) (*BroadcastMessage, error) {
	if len(be.recipients) == 0 {
		return nil, ErrNoRecipients
	}

	// Generate random session key
	sessionKey := make([]byte, KeySize)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, err
	}

	// Encrypt message with session key
	encryptedMsg, err := EncryptWithKey(sessionKey, plaintext)
	if err != nil {
		return nil, err
	}

	// Encrypt session key for each recipient
	recipientKeys := make(map[string][]byte)
	for id, key := range be.recipients {
		encKey, err := EncryptWithKey(key, sessionKey)
		if err != nil {
			return nil, err
		}
		recipientKeys[id] = encKey
	}

	// Create sender proof
	mac := hmac.New(sha256.New, be.senderKey[:])
	mac.Write(encryptedMsg)
	proof := mac.Sum(nil)

	return &BroadcastMessage{
		EncryptedMessage: encryptedMsg,
		RecipientKeys:    recipientKeys,
		SenderProof:      proof,
	}, nil
}

// ReceiveBroadcast decrypts a broadcast message.
func ReceiveBroadcast(msg *BroadcastMessage, recipientID string, recipientKey []byte) ([]byte, error) {
	encryptedSessionKey, ok := msg.RecipientKeys[recipientID]
	if !ok {
		return nil, ErrMemberNotFound
	}

	// Decrypt session key
	sessionKey, err := DecryptWithKey(recipientKey, encryptedSessionKey, nil)
	if err != nil {
		return nil, err
	}

	// Decrypt message
	return DecryptWithKey(sessionKey, msg.EncryptedMessage, nil)
}

// VerifySender verifies the sender proof.
func VerifySender(msg *BroadcastMessage, senderKey []byte) bool {
	mac := hmac.New(sha256.New, senderKey)
	mac.Write(msg.EncryptedMessage)
	expected := mac.Sum(nil)
	return hmac.Equal(msg.SenderProof, expected)
}

// Recipients returns list of recipient IDs.
func (be *BroadcastEncryption) Recipients() []string {
	recipients := make([]string, 0, len(be.recipients))
	for id := range be.recipients {
		recipients = append(recipients, id)
	}
	return recipients
}

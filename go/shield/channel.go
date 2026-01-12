package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Protocol constants
const (
	protocolVersion  = 1
	maxMessageSize   = 16 * 1024 * 1024 // 16 MB
	maxHandshakeSize = 1024
)

// Handshake message types
const (
	handshakeClientHello = 1
	handshakeServerHello = 2
	handshakeFinished    = 3
)

// Channel errors
var (
	ErrInvalidHandshake  = errors.New("shield: invalid handshake")
	ErrUnsupportedVersion = errors.New("shield: unsupported protocol version")
	ErrMessageTooLarge   = errors.New("shield: message too large")
	ErrConnectionClosed  = errors.New("shield: connection closed")
)

// ChannelConfig holds channel configuration.
type ChannelConfig struct {
	Password           string
	Service            string
	Iterations         int
	HandshakeTimeoutMs int64
}

// NewChannelConfig creates a new channel configuration.
func NewChannelConfig(password, service string) *ChannelConfig {
	return &ChannelConfig{
		Password:           password,
		Service:            service,
		Iterations:         200000,
		HandshakeTimeoutMs: 30000,
	}
}

// WithIterations sets custom PBKDF2 iterations.
func (c *ChannelConfig) WithIterations(iterations int) *ChannelConfig {
	c.Iterations = iterations
	return c
}

// WithTimeout sets handshake timeout.
func (c *ChannelConfig) WithTimeout(timeoutMs int64) *ChannelConfig {
	c.HandshakeTimeoutMs = timeoutMs
	return c
}

// ShieldChannel provides encrypted bidirectional communication.
type ShieldChannel struct {
	conn    io.ReadWriteCloser
	session *RatchetSession
	service string
}

// Connect initiates a client connection with PAKE handshake.
func Connect(conn io.ReadWriteCloser, config *ChannelConfig) (*ShieldChannel, error) {
	ch := &ShieldChannel{conn: conn, service: config.Service}

	// Step 1: Generate client salt and send ClientHello
	clientSalt := make([]byte, 16)
	if _, err := rand.Read(clientSalt); err != nil {
		return nil, err
	}
	if err := ch.sendHandshake(handshakeClientHello, clientSalt); err != nil {
		return nil, err
	}

	// Step 2: Receive ServerHello
	serverHello, err := ch.recvHandshake(handshakeServerHello)
	if err != nil {
		return nil, err
	}
	if len(serverHello) != 48 {
		return nil, ErrInvalidHandshake
	}

	finalSalt := serverHello[:16]
	serverContribution := serverHello[16:48]

	// Step 3: Derive our contribution and send it
	clientContribution := PAKEDerive(config.Password, finalSalt, "client", config.Iterations)
	if err := ch.sendHandshake(handshakeFinished, clientContribution); err != nil {
		return nil, err
	}

	// Compute session key
	sessionKey := ch.computeSessionKey(config, finalSalt, clientContribution, serverContribution)

	// Create ratchet session
	ch.session, err = NewRatchetSession(sessionKey, true)
	if err != nil {
		return nil, err
	}

	// Exchange confirmations
	if err := ch.sendConfirmation(sessionKey, true); err != nil {
		return nil, err
	}
	if err := ch.verifyConfirmation(sessionKey, false); err != nil {
		return nil, err
	}

	return ch, nil
}

// Accept waits for a client connection with PAKE handshake.
func Accept(conn io.ReadWriteCloser, config *ChannelConfig) (*ShieldChannel, error) {
	ch := &ShieldChannel{conn: conn, service: config.Service}

	// Step 1: Receive ClientHello
	clientHello, err := ch.recvHandshake(handshakeClientHello)
	if err != nil {
		return nil, err
	}
	if len(clientHello) != 16 {
		return nil, ErrInvalidHandshake
	}

	// Mix salts
	serverSalt := make([]byte, 16)
	if _, err := rand.Read(serverSalt); err != nil {
		return nil, err
	}
	finalSalt := make([]byte, 16)
	for i := 0; i < 16; i++ {
		finalSalt[i] = serverSalt[i] ^ clientHello[i]
	}

	// Derive server contribution
	serverContribution := PAKEDerive(config.Password, finalSalt, "server", config.Iterations)

	// Step 2: Send ServerHello
	serverHello := make([]byte, 48)
	copy(serverHello[:16], finalSalt)
	copy(serverHello[16:], serverContribution)
	if err := ch.sendHandshake(handshakeServerHello, serverHello); err != nil {
		return nil, err
	}

	// Step 3: Receive client contribution
	clientFinished, err := ch.recvHandshake(handshakeFinished)
	if err != nil {
		return nil, err
	}
	if len(clientFinished) != 32 {
		return nil, ErrInvalidHandshake
	}

	// Compute session key
	sessionKey := ch.computeSessionKey(config, finalSalt, serverContribution, clientFinished)

	// Create ratchet session
	ch.session, err = NewRatchetSession(sessionKey, false)
	if err != nil {
		return nil, err
	}

	// Exchange confirmations
	if err := ch.verifyConfirmation(sessionKey, true); err != nil {
		return nil, err
	}
	if err := ch.sendConfirmation(sessionKey, false); err != nil {
		return nil, err
	}

	return ch, nil
}

// Send encrypts and sends a message.
func (ch *ShieldChannel) Send(data []byte) error {
	if len(data) > maxMessageSize {
		return ErrMessageTooLarge
	}

	encrypted, err := ch.session.Encrypt(data)
	if err != nil {
		return err
	}

	return ch.writeFrame(encrypted)
}

// Recv receives and decrypts a message.
func (ch *ShieldChannel) Recv() ([]byte, error) {
	encrypted, err := ch.readFrame()
	if err != nil {
		return nil, err
	}

	return ch.session.Decrypt(encrypted)
}

// Service returns the service identifier.
func (ch *ShieldChannel) Service() string {
	return ch.service
}

// MessagesSent returns the send message count.
func (ch *ShieldChannel) MessagesSent() uint64 {
	return ch.session.SendCounter()
}

// MessagesReceived returns the receive message count.
func (ch *ShieldChannel) MessagesReceived() uint64 {
	return ch.session.RecvCounter()
}

// Close closes the channel.
func (ch *ShieldChannel) Close() error {
	return ch.conn.Close()
}

// --- Internal helpers ---

func (ch *ShieldChannel) computeSessionKey(config *ChannelConfig, salt, localContribution, remoteContribution []byte) []byte {
	baseKey := PAKECombine(localContribution, remoteContribution)
	passwordKey := PAKEDerive(config.Password, salt, "session", config.Iterations)

	combined := make([]byte, 64)
	copy(combined[:32], baseKey)
	copy(combined[32:], passwordKey)

	h := sha256.Sum256(combined)
	return h[:]
}

func (ch *ShieldChannel) sendHandshake(msgType byte, data []byte) error {
	frame := make([]byte, 4+len(data))
	frame[0] = protocolVersion
	frame[1] = msgType
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)

	_, err := ch.conn.Write(frame)
	return err
}

func (ch *ShieldChannel) recvHandshake(expectedType byte) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(ch.conn, header); err != nil {
		return nil, err
	}

	if header[0] != protocolVersion {
		return nil, ErrUnsupportedVersion
	}

	if header[1] != expectedType {
		return nil, ErrInvalidHandshake
	}

	length := binary.BigEndian.Uint16(header[2:4])
	if length > maxHandshakeSize {
		return nil, ErrInvalidHandshake
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(ch.conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

func (ch *ShieldChannel) sendConfirmation(sessionKey []byte, isClient bool) error {
	label := "server-confirm"
	if isClient {
		label = "client-confirm"
	}

	mac := hmac.New(sha256.New, sessionKey)
	mac.Write([]byte(label))
	confirm := mac.Sum(nil)[:16]

	return ch.writeFrame(confirm)
}

func (ch *ShieldChannel) verifyConfirmation(sessionKey []byte, expectClient bool) error {
	received, err := ch.readFrame()
	if err != nil {
		return err
	}
	if len(received) != 16 {
		return ErrInvalidHandshake
	}

	label := "server-confirm"
	if expectClient {
		label = "client-confirm"
	}

	mac := hmac.New(sha256.New, sessionKey)
	mac.Write([]byte(label))
	expected := mac.Sum(nil)[:16]

	if subtle.ConstantTimeCompare(received, expected) != 1 {
		return ErrAuthenticationFailed
	}

	return nil
}

func (ch *ShieldChannel) writeFrame(data []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(data)))

	if _, err := ch.conn.Write(header); err != nil {
		return err
	}
	_, err := ch.conn.Write(data)
	return err
}

func (ch *ShieldChannel) readFrame() ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(ch.conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header)
	if length > maxMessageSize {
		return nil, ErrMessageTooLarge
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(ch.conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// ShieldListener listens for multiple Shield connections.
type ShieldListener struct {
	listener net.Listener
	config   *ChannelConfig
}

// NewShieldListener creates a new Shield listener.
func NewShieldListener(listener net.Listener, config *ChannelConfig) *ShieldListener {
	return &ShieldListener{
		listener: listener,
		config:   config,
	}
}

// Accept accepts the next connection.
func (l *ShieldListener) Accept() (*ShieldChannel, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}

	return Accept(conn, l.config)
}

// Config returns the configuration.
func (l *ShieldListener) Config() *ChannelConfig {
	return l.config
}

// Close closes the listener.
func (l *ShieldListener) Close() error {
	return l.listener.Close()
}

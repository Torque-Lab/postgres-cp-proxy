package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"postgres-cp-proxy/control_plane"
	"strings"
)

/* do this in control plane
SaltedPassword = PBKDF2(password, salt, iterations)
ClientKey = HMAC(SaltedPassword, "Client Key")
StoredKey = HASH(ClientKey)
ServerKey = HMAC(SaltedPassword, "Server Key")
The server stores StoredKey, ServerKey, salt, and iteration count.*/

// --- Postgres wire helpers ---
func SendAuthenticationSASL(client net.Conn) error {
	buf := new(bytes.Buffer)
	buf.WriteByte('R')
	mechanism := []byte("SCRAM-SHA-256\x00")
	length := int32(4 + 4 + len(mechanism))
	binary.Write(buf, binary.BigEndian, length)
	binary.Write(buf, binary.BigEndian, int32(10)) // AuthenticationSASL
	buf.Write(mechanism)
	_, err := client.Write(buf.Bytes())
	return err
}

func SendSASLContinue(client net.Conn, msg string) error {
	buf := new(bytes.Buffer)
	buf.WriteByte('R')
	data := []byte(msg)
	length := int32(4 + 4 + len(data))
	binary.Write(buf, binary.BigEndian, length)
	binary.Write(buf, binary.BigEndian, int32(11)) // SASLContinue
	buf.Write(data)
	_, err := client.Write(buf.Bytes())
	return err
}

func SendSASLFinal(client net.Conn, msg string) error {
	buf := new(bytes.Buffer)
	buf.WriteByte('R')
	data := []byte(msg)
	length := int32(4 + 4 + len(data))
	binary.Write(buf, binary.BigEndian, length)
	binary.Write(buf, binary.BigEndian, int32(12)) // SASLFinal
	buf.Write(data)
	_, err := client.Write(buf.Bytes())
	return err
}

func SendAuthenticationOk(client net.Conn) error {
	buf := new(bytes.Buffer)
	buf.WriteByte('R')
	binary.Write(buf, binary.BigEndian, int32(8))
	binary.Write(buf, binary.BigEndian, int32(0))
	_, err := client.Write(buf.Bytes())
	return err
}

func SendError(client net.Conn, msg string) {
	buf := new(bytes.Buffer)
	buf.WriteByte('E') // ErrorResponse message type

	payload := new(bytes.Buffer)

	// Severity field: ERROR or FATAL
	payload.WriteByte('S')
	payload.WriteString("ERROR")
	payload.WriteByte(0)

	// SQLSTATE code (28000 = invalid authorization)
	payload.WriteByte('C')
	payload.WriteString("28000")
	payload.WriteByte(0)

	// Human-readable message
	payload.WriteByte('M')
	payload.WriteString(msg)
	payload.WriteByte(0)

	// Message terminator
	payload.WriteByte(0)

	binary.Write(buf, binary.BigEndian, int32(payload.Len()+4))
	buf.Write(payload.Bytes())

	// Send to client
	if _, err := client.Write(buf.Bytes()); err != nil {
		fmt.Println("Failed to send ErrorResponse:", err)
		return
	}

	fmt.Println("Sent ErrorResponse to client:", msg)
}

func ComputeHMAC(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func ComputeHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func XORBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func ReadClientSASLMessage(client net.Conn) (string, error) {
	var msgType [1]byte
	if _, err := client.Read(msgType[:]); err != nil {
		return "", err
	}
	if msgType[0] != 'p' {
		return "", fmt.Errorf("expected SASL message, got %q", msgType[0])
	}

	var length uint32
	if err := binary.Read(client, binary.BigEndian, &length); err != nil {
		return "", err
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(client, payload); err != nil {
		return "", err
	}

	return string(payload[:len(payload)-1]), nil // remove trailing NUL
}

// Parse client-first-message: extract username and nonce
func ParseClientFirstMessage(msg string) (username, nonce string, err error) {
	// client-first-message format: "n=username,r=clientnonce"
	parts := strings.Split(msg, ",")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid client first message")
	}
	username = strings.TrimPrefix(parts[0], "n=")
	nonce = strings.TrimPrefix(parts[1], "r=")
	return username, nonce, nil
}

// Parse client-final-message: extract proof
func ParseClientFinalMessage(msg string) (proof string, err error) {
	// client-final-message contains "c=...,r=...,p=base64proof"
	for _, part := range strings.Split(msg, ",") {
		if strings.HasPrefix(part, "p=") {
			proof = strings.TrimPrefix(part, "p=")
			return proof, nil
		}
	}
	return "", fmt.Errorf("proof not found in client final message")
}

// Verify client proof using StoredKey (control plane)
func VerifyClientProof(clientProofB64 string, storedKey []byte, authMessage string) bool {
	clientProof, err := base64.StdEncoding.DecodeString(clientProofB64)
	if err != nil {
		return false
	}
	clientKey := XORBytes(clientProof, ComputeHMAC(storedKey, []byte(authMessage)))
	storedKeyCheck := ComputeHash(clientKey)
	return hmac.Equal(storedKeyCheck, storedKey)
}

func ComputeServerSignature(serverKey []byte, authMessage string) string {
	sig := ComputeHMAC(serverKey, []byte(authMessage))
	return base64.StdEncoding.EncodeToString(sig)
}

func HandleSCRAM(client net.Conn, username_db_name string) error {
	cred, ok := control_plane.GetUserCredential(username_db_name)
	if !ok {
		return fmt.Errorf("user %q not found", username_db_name)
	}

	if err := SendAuthenticationSASL(client); err != nil {
		return err
	}

	clientFirst, err := ReadClientSASLMessage(client)
	if err != nil {
		return err
	}

	clientUser, clientNonce, err := ParseClientFirstMessage(clientFirst)
	if err != nil {
		return err
	}
	username := strings.Split(username_db_name, ":")[0]
	if clientUser != username {
		return fmt.Errorf("username mismatch")
	}

	// Build server-first-message
	serverRandom, error := generateNonce(18)
	if error != nil {
		return error
	}
	serverNonce := clientNonce + serverRandom // random in prod
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", serverNonce, cred.Salt, cred.Iterations)
	if err := SendSASLContinue(client, serverFirst); err != nil {
		return err
	}

	clientFinal, err := ReadClientSASLMessage(client)
	if err != nil {
		return err
	}
	clientProof, err := ParseClientFinalMessage(clientFinal)
	if err != nil {
		return err
	}

	authMessage := clientFirst + "," + serverFirst + "," + clientFinal

	storedKeyBytes, _ := base64.StdEncoding.DecodeString(cred.StoredKey)
	serverKeyBytes, _ := base64.StdEncoding.DecodeString(cred.ServerKey)

	if !VerifyClientProof(clientProof, storedKeyBytes, authMessage) {
		return fmt.Errorf("client proof verification failed")
	}

	serverSignature := ComputeServerSignature(serverKeyBytes, authMessage)
	if err := SendSASLFinal(client, "v="+serverSignature); err != nil {
		return err
	}

	return SendAuthenticationOk(client)
}

func generateNonce(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(bytes), nil
}

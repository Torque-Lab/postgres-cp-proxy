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

/*
	do this in control plane

SaltedPassword = PBKDF2(password, salt, iterations)
ClientKey = HMAC(SaltedPassword, "Client Key")
StoredKey = HASH(ClientKey)
ServerKey = HMAC(SaltedPassword, "Server Key")
The server stores StoredKey, ServerKey, salt, and iteration count.
*/
func SendAuthenticationSASL(conn net.Conn) error {
	buf := new(bytes.Buffer)

	// Message type
	buf.WriteByte('R')

	// Mechanism list
	mech := []byte("SCRAM-SHA-256\x00") // each ends with \0
	endMarker := []byte{0}              // terminator (signals end of list)

	// Compute total length:
	// 4 (length field itself) + 4 (auth code) + len(mech) + len(endMarker)
	totalLen := int32(4 + 4 + len(mech) + len(endMarker))
	binary.Write(buf, binary.BigEndian, totalLen)

	// Auth code = 10 (AuthenticationSASL)
	binary.Write(buf, binary.BigEndian, int32(10))

	// Mechanisms + terminator
	buf.Write(mech)
	buf.Write(endMarker)

	b := buf.Bytes()

	fmt.Printf("SendAuthenticationSASL bytes: % x\n", b)
	fmt.Printf("TotalLen=%d, AuthCode=10\n", totalLen)

	_, err := conn.Write(b)
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

// func SendAuthenticationOk(client net.Conn) error {
// 	buf := new(bytes.Buffer)
// 	buf.WriteByte('R')
// 	binary.Write(buf, binary.BigEndian, int32(8))
// 	binary.Write(buf, binary.BigEndian, int32(0))
// 	_, err := client.Write(buf.Bytes())
// 	return err
// }

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
func ReadClientSASLMessage(conn net.Conn) (mechanism string, initialResp []byte, clientFirst string, err error) {
	var t [1]byte
	if _, err = io.ReadFull(conn, t[:]); err != nil {
		return "", nil, "", err
	}
	if t[0] != 'p' {
		return "", nil, "", fmt.Errorf("expected 'p' (SASLInitialResponse), got %q", t[0])
	}

	var length uint32
	if err = binary.Read(conn, binary.BigEndian, &length); err != nil {
		return "", nil, "", err
	}

	payload := make([]byte, length-4)
	if _, err = io.ReadFull(conn, payload); err != nil {
		return "", nil, "", err
	}

	// Try to find null after mechanism
	nullIdx := bytes.IndexByte(payload, 0)

	if nullIdx == -1 {
		//  fallback: assume the mechanism name is known and fixed (like SCRAM-SHA-256)
		// and that the next 4 bytes are the int32 initial response length
		if len(payload) < len("SCRAM-SHA-256")+4 {
			return "", nil, "", fmt.Errorf("invalid SASL payload: too short to parse without null terminator")
		}
		mechanism = "SCRAM-SHA-256"
		offset := len(mechanism)
		initialLen := int(binary.BigEndian.Uint32(payload[offset : offset+4]))
		rest := payload[offset+4:]
		if initialLen == -1 {
			return mechanism, nil, "", nil
		}
		if initialLen > len(rest) {
			initialLen = len(rest)
		}
		initialResp = rest[:initialLen]
		clientFirst = string(initialResp)

		fmt.Printf("[WARN] missing null terminator; assumed mechanism=%q\n", mechanism)
		fmt.Printf("ReadClientSASLMessage: fallback parse initialLen=%d actual=%d\n", initialLen, len(initialResp))
		fmt.Printf("initialResp text: %q\n", clientFirst)
		return mechanism, initialResp, clientFirst, nil
	}

	// Normal path with null terminator
	mechanism = string(payload[:nullIdx])
	if len(payload) < nullIdx+5 {
		return mechanism, nil, "", fmt.Errorf("invalid SASL payload: missing initial response length")
	}
	initialLen := int(binary.BigEndian.Uint32(payload[nullIdx+1 : nullIdx+5]))
	rest := payload[nullIdx+5:]
	if initialLen == -1 {
		return mechanism, nil, "", nil
	}
	if initialLen > len(rest) {
		initialLen = len(rest)
	}
	initialResp = rest[:initialLen]
	clientFirst = string(initialResp)

	fmt.Printf("ReadClientSASLMessage: mech=%q initialLen=%d actual=%d\n", mechanism, initialLen, len(initialResp))
	fmt.Printf("initialResp text: %q\n", clientFirst)
	return mechanism, initialResp, clientFirst, nil
}

// parseClientFirst extracts username (n=) from the SCRAM client-first string.
// It handles GS2 header like "n,," or "y,authzid," followed by "n=<user>,r=<nonce>,..."
// Change the return signature
func parseClientFirst(clientFirst string) (username string, nonce string, clientFirstBare string, err error) {
	// clientFirst expected like: "<gs2-header>,<client-first-bare>"
	parts := strings.SplitN(clientFirst, ",", 3)
	if len(parts) < 3 {
		// fallback: try to find "n=" directly
		username, nonce, err := parseNfromBare(clientFirst)
		return username, nonce, clientFirst, err // Assume it was already bare
	}

	clientFirstBare = parts[2] // This is the part we need
	username, nonce, err = parseNfromBare(clientFirstBare)
	return username, nonce, clientFirstBare, err
}
func parseNfromBare(bare string) (username string, nonce string, err error) {
	// Bare is like "n=alice,r=abc..."
	fields := strings.Split(bare, ",")
	for _, f := range fields {
		if strings.HasPrefix(f, "n=") {
			username = strings.TrimPrefix(f, "n=")
		}
		if strings.HasPrefix(f, "r=") {
			nonce = strings.TrimPrefix(f, "r=")
		}
	}
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

func VerifyClientProof(clientProofB64 string, storedKey []byte, authMessage string) bool {
	clientProof, err := base64.StdEncoding.DecodeString(clientProofB64)
	fmt.Printf("clientProofB64:from previous step %s\n", clientProofB64)
	fmt.Printf("clientProof (decoded): %x\n", clientProof)
	fmt.Printf("storedKey: %x\n", storedKey)
	fmt.Printf("authMessage: %s\n", authMessage)
	if err != nil {
		return false
	}
	clientKey := XORBytes(clientProof, ComputeHMAC(storedKey, []byte(authMessage)))
	fmt.Printf("clientKey: %x\n", clientKey)
	storedKeyCheck := ComputeHash(clientKey)
	fmt.Printf("storedKeyCheck: %x\n", storedKeyCheck)
	return hmac.Equal(storedKeyCheck, storedKey)
}

func ComputeServerSignature(serverKey []byte, authMessage string) string {
	sig := ComputeHMAC(serverKey, []byte(authMessage))
	return base64.StdEncoding.EncodeToString(sig)
}

func HandleSCRAM(client net.Conn, username_db_name string) (string, error) {
	cred, ok := control_plane.GetUserCredential(username_db_name)
	if !ok {
		return "", fmt.Errorf("user %q not found", username_db_name)
	}

	if err := SendAuthenticationSASL(client); err != nil {
		return "", err
	}

	_, _, clientFirst, err := ReadClientSASLMessage(client)
	if err != nil {
		return "", err
	}

	clientUser, clientNonce, clientFirstBare, err := parseClientFirst(clientFirst)
	if err != nil {
		return "", err
	}

	username := strings.Split(username_db_name, ":")[0]

	//  If client didn't send username, fix it.
	if clientUser == "" {
		fmt.Println(" clientFirst missing username, populating from startup:", username)
		// clientFirst = strings.Replace(clientFirst, "n=,", "n="+username+",", 1)
		clientUser = username
	}

	// Build server-first-message
	serverRandom, error := generateNonce(18)
	if error != nil {
		return "", error
	}
	serverNonce := clientNonce + serverRandom
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", serverNonce, cred.Salt, cred.Iterations)
	if err := SendSASLContinue(client, serverFirst); err != nil {
		fmt.Println("SendSASLContinue error:", err)
		return "", err
	}

	clientFinal, err := ReadClientSASLResponse(client)
	if err != nil {
		return "", err
	}
	clientProof, err := ParseClientFinalMessage(clientFinal)
	if err != nil {
		return "", err
	}
	clientFinalBare := strings.Split(clientFinal, ",p=")[0]

	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalBare

	storedKeyBytes, _ := base64.StdEncoding.DecodeString(cred.StoredKey)
	serverKeyBytes, _ := base64.StdEncoding.DecodeString(cred.ServerKey)
	if !VerifyClientProof(clientProof, storedKeyBytes, authMessage) {
		fmt.Println("VerifyClientProof error:", err)
		return "", fmt.Errorf("client proof verification failed")
	}

	serverSignature := ComputeServerSignature(serverKeyBytes, authMessage)
	if err := SendSASLFinal(client, "v="+serverSignature); err != nil {
		fmt.Println("SendSASLFinal error:", err)
		return "", err
	}
	fmt.Println("SCRAM authentication successful")
	return "auth_scram_success", nil
}

func generateNonce(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(bytes), nil
}

func ReadClientSASLResponse(conn net.Conn) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(conn, t[:]); err != nil {
		return "", err
	}
	if t[0] != 'p' {
		return "", fmt.Errorf("expected 'p' (SASLResponse), got %q", t[0])
	}

	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return "", err
	}

	if length < 4 {
		return "", fmt.Errorf("invalid SASLResponse length: %d", length)
	}

	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return "", err
	}

	fmt.Printf("ReadClientSASLResponse: data=%q\n", string(payload))
	return string(payload), nil
}

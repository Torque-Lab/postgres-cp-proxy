package protocol_wire_parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"postgres-cp-proxy/auth"
	"postgres-cp-proxy/control_plane"
	"sync"
)

func HandleConnection(client net.Conn) {
	defer client.Close()

	var length uint32
	if err := binary.Read(client, binary.BigEndian, &length); err != nil {
		fmt.Println("Error reading startup length:", err)
		return
	}
	payloadLength := int(length - 4)
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(client, payload); err != nil {
		fmt.Println("Error reading startup payload:", err)
		return
	}

	if len(payload) < 4 {
		fmt.Println("Startup payload too short")
		return
	}

	protoVersion := binary.BigEndian.Uint32(payload[:4])
	switch protoVersion {
	case 196608: // normal
	case 80877103: // SSL request
		fmt.Println("Client requested SSL, replying 'N' (No SSL)")
		if _, err := client.Write([]byte("N")); err != nil {
			fmt.Println("Failed to write SSL reject:", err)
			return
		}
		// Re-read StartupMessage
		if err := binary.Read(client, binary.BigEndian, &length); err != nil {
			fmt.Println("Error re-reading length:", err)
			return
		}
		payloadLength = int(length - 4)
		payload = make([]byte, payloadLength)
		if _, err := io.ReadFull(client, payload); err != nil {
			fmt.Println("Error re-reading payload:", err)
			return
		}
		protoVersion = binary.BigEndian.Uint32(payload[:4])
		if protoVersion != 196608 {
			fmt.Println("Still unsupported protocol:", protoVersion)
			return
		}
	default:
		fmt.Println("Unsupported protocol version:", protoVersion)
		return
	}

	params := parseKeyValue(payload[4:])
	user := params["user"]
	db := params["database"]
	if user == "" || db == "" {
		fmt.Println("missing user or database in startup")
		return
	}

	// SCRAM authentication
	if err := auth.HandleSCRAM(client, user); err != nil {
		fmt.Println("SCRAM authentication failed:", err)
		auth.SendError(client, err.Error())
		return
	}

	// Forward to backend
	key := user + ":" + db
	backendAddr, err := control_plane.GetBackendAddress(key)
	if err != nil {
		fmt.Println("failed to get backend for key:", key, err)
		return
	}

	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		fmt.Println("error dialing backend:", err)
		return
	}
	defer backendConn.Close()

	// Forward startup message to backend
	if err := binary.Write(backendConn, binary.BigEndian, length); err != nil {
		fmt.Println("error forwarding startup length to backend:", err)
		return
	}
	if _, err := backendConn.Write(payload); err != nil {
		fmt.Println("error forwarding startup payload to backend:", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go proxyPipe(&wg, client, backendConn)
	go proxyPipe(&wg, backendConn, client)
	wg.Wait()
}
func parseKeyValue(b []byte) map[string]string {
	m := make(map[string]string)
	parsed := bytes.Split(b, []byte{0})
	for i := 0; i < len(parsed)-1; i += 2 {
		key := string(parsed[i])
		value := string(parsed[i+1])
		if key == "" {
			break
		}
		m[key] = value
	}
	return m
}
func proxyPipe(wg *sync.WaitGroup, src net.Conn, dst net.Conn) {
	defer wg.Done()
	io.Copy(dst, src)
}

package protocol_wire_parser

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"postgres-cp-proxy/auth"
	"postgres-cp-proxy/control_plane"
	"sync"
)

var certMutex = &sync.Mutex{}

func HandleConnection(client net.Conn) {
	defer client.Close()
	certPath := "/etc/ssl/certs/tls.crt"
	keyPath := "/etc/ssl/certs/tls.key"
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
		fmt.Println("Client requested SSL, replying 'S' ")
		if _, err := client.Write([]byte("S")); err != nil {
			fmt.Println("Failed to write SSL Accept:", err)
			return
		}
		certMutex.Lock()
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		certMutex.Unlock()
		if err != nil {
			log.Println("failed to load cert:", err)
		}
		tlsConfig := &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
			PreferServerCipherSuites: true,
		}
		tlsConn := tls.Server(client, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			fmt.Println("TLS handshake failed:", err)
			return
		}
		client = tlsConn

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
	fmt.Println("User:", user, "Database:", db)

	// SCRAM authentication
	key := user + ":" + db
	if err := auth.HandleSCRAM(client, key); err != nil {
		fmt.Println("SCRAM authentication failed:", err)
		auth.SendError(client, err.Error())
		return
	}

	// Forward to backend
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

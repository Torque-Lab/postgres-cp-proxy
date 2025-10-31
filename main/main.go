package main

import (
	"fmt"
	"net"
	"os"
	"postgres-cp-proxy/control_plane"
	_ "postgres-cp-proxy/env_config"
	"postgres-cp-proxy/protocol_wire_parser"
)

var proxy_port = os.Getenv("PROXY_PORT")

func main() {
	go control_plane.StartUpdateServer()
	listener, err := net.Listen("tcp", ":"+proxy_port)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	fmt.Printf("Proxy listening on:%s\n", proxy_port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err.Error())
			continue
		}
		go protocol_wire_parser.HandleConnection(conn)
	}
}

package main

import (
	"fmt"
	"net"
	"postgres-cp-proxy/control_plane"
	"postgres-cp-proxy/protocol_wire_parser"
)

func main() {
	go control_plane.StartUpdateServer()
	listener, err := net.Listen("tcp", ":5455")
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	}
	fmt.Println("Proxy listening on :5455")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err.Error())
			continue
		}
		go protocol_wire_parser.HandleConnection(conn)
	}
}

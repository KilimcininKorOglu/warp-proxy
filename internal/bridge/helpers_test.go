package bridge

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeSocks starts a minimal SOCKS5 proxy that relays to real targets,
// standing in for the warp-cli proxy.
func fakeSocks(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake socks: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveSocks(ln)
	return ln.Addr().String()
}

func serveSocks(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleSocksConn(conn)
	}
}

func handleSocksConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	conn.Write([]byte{5, 0})

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = string(name)
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(br, port); err != nil {
		return
	}
	targetPort := int(port[0])<<8 | int(port[1])
	target, err := net.Dial("tcp", host+":"+strconv.Itoa(targetPort))
	if err != nil {
		conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { io.Copy(target, br); done <- struct{}{} }()
	go func() { io.Copy(conn, target); done <- struct{}{} }()
	<-done
}

package smtpclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestSendPinsResolvedSMTPAddress(t *testing.T) {
	var lookedUp string
	var dialed string
	err := sendWithResolvers(
		context.Background(), "smtp.example", 587, "", "", "from@example.com", []string{"to@example.com"}, []byte("Subject: test\r\n\r\nbody"), false,
		func(_ context.Context, host string) ([]net.IPAddr, error) {
			lookedUp = host
			return []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}}, nil
		},
		func(_ context.Context, network, address string) (net.Conn, error) {
			dialed = network + ":" + address
			return nil, errors.New("test stop")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "test stop") {
		t.Fatalf("expected dial error, got %v", err)
	}
	if lookedUp != "smtp.example" {
		t.Fatalf("lookup host = %q", lookedUp)
	}
	if dialed != "tcp:203.0.113.9:587" {
		t.Fatalf("dial address = %q", dialed)
	}
}

func TestSendRejectsPrivateSMTPAddressBeforeDial(t *testing.T) {
	dialed := false
	err := sendWithResolvers(
		context.Background(), "smtp.example", 587, "", "", "from@example.com", []string{"to@example.com"}, nil, true,
		func(_ context.Context, _ string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.10")}}, nil
		},
		func(_ context.Context, _, _ string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("should not dial")
		},
	)
	if err == nil || !strings.Contains(err.Error(), "private/internal") {
		t.Fatalf("expected private-address rejection, got %v", err)
	}
	if dialed {
		t.Fatal("private SMTP address was dialed")
	}
}

func TestSendOnConnectionRejectsAuthenticatedCleartext(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer serverConn.Close()
		_, _ = serverConn.Write([]byte("220 smtp.example ESMTP ready\r\n"))
		buf := make([]byte, 4096)
		n, err := serverConn.Read(buf)
		if err != nil {
			return
		}
		if !strings.HasPrefix(string(buf[:n]), "EHLO ") && !strings.HasPrefix(string(buf[:n]), "HELO ") {
			return
		}
		_, _ = serverConn.Write([]byte("250-smtp.example\r\n250 OK\r\n"))
	}()

	err := sendOnConnection(context.Background(), clientConn, "smtp.example", "user", "secret", "from@example.com", []string{"to@example.com"}, []byte("Subject: test\r\n\r\nbody"))
	<-serverDone
	if err == nil || !strings.Contains(err.Error(), "refusing authenticated cleartext SMTP") {
		t.Fatalf("expected authenticated cleartext rejection, got %v", err)
	}
}

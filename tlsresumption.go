// Package tlsresumption provides utilities for implementing out of band sharing of client session
// states for tls session resumption.
package tlsresumption

import (
	"encoding/base64"
	"encoding/json"
	"net"

	"github.com/getlantern/errors"
	"github.com/getlantern/golog"
	utls "github.com/refraction-networking/utls"
)

var (
	log = golog.LoggerFor("tlsresumption")
)

// MakeClientSessionStates makes num client session states for connecting to the TLS server at the given
// address. It connects to the server and handshakes num times and returns as many client session states
// as it can successfully build, returning the latest error.
//
// Note, this does not verify the server's certificate so is potentially susceptible to MITM attacks.
func MakeClientSessionStates(addr string, num int) ([]string, error) {
	result := make([]string, 0, num)

	cache := utls.NewLRUClientSessionCache(0)
	var finalErr error
	for i := 0; i < num; i++ {
		conn, err := dialUTLS(cache, nil, addr)
		if err != nil {
			finalErr = err
			continue
		}
		conn.Close()
		css, ok := cache.Get(addr)
		if !ok {
			finalErr = errors.New("no client session state found in cache")
			continue
		}
		ssString, err := SerializeClientSessionState(css)
		if err != nil {
			finalErr = err
			continue
		}

		result = append(result, ssString)
	}

	return result, finalErr
}

// ParseClientSessionState parses the serialized client session state into a utls.ClientSessionState
func ParseClientSessionState(serialized string) (*utls.ClientSessionState, error) {
	b, err := base64.StdEncoding.DecodeString(serialized)
	if err != nil {
		return nil, errors.New("unable to base64 decode serialized client session state: %v", err)
	}
	sss := &serializedClientSessionState{}
	err = json.Unmarshal(b, sss)
	if err != nil {
		return nil, err
	}

	state, err := utls.ParseSessionState(sss.SessionState)
	if err != nil {
		return nil, errors.New("unable to parse session state: %v", err)
	}
	cs, err := utls.NewResumptionState(sss.SessionTicket, state)
	if err != nil {
		return nil, errors.New("unable to create a resumption state: %v", err)
	}
	return cs, nil
}

func dialUTLS(cache utls.ClientSessionCache, ss *utls.ClientSessionState, addr string) (*utls.UConn, error) {
	cfg := &utls.Config{
		InsecureSkipVerify: true,
		ServerName:         addr,
		ClientSessionCache: cache,
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, errors.New("unable to dial %v: %v", addr, err)
	}
	uconn := utls.UClient(conn, cfg, utls.HelloChrome_Auto)
	if ss != nil {
		ticket, state, err := ss.ResumptionState()
		if err != nil {
			conn.Close()
			return nil, errors.New("unable to get resumption state: %v", err)
		}
		err = uconn.SetSessionTicketExtension(&utls.SessionTicketExtension{
			Initialized: true,
			Ticket:      ticket,
			Session:     state,
		})
		if err != nil {
			conn.Close()
			return nil, errors.New("unable to set session state: %v", err)
		}
	}
	if handshakeErr := uconn.Handshake(); handshakeErr != nil {
		conn.Close()
		return nil, errors.New("error handshaking with %v: %v", addr, handshakeErr)
	}
	return uconn, nil
}

type serializedClientSessionState struct {
	SessionState  []byte
	SessionTicket []byte
}

// SerializeClientSessionState serializes a ClientSessionState into a string representation of the same.
func SerializeClientSessionState(ss *utls.ClientSessionState) (string, error) {

	ticket, state, err := ss.ResumptionState()
	if err != nil {
		return "", errors.New("unable to get resumption state: %v", err)
	}
	stateBytes, err := state.Bytes()
	if err != nil {
		return "", errors.New("unable to serialize session state: %v", err)
	}

	sss := &serializedClientSessionState{
		SessionState:  stateBytes,
		SessionTicket: ticket,
	}

	b, err := json.Marshal(sss)
	if err != nil {
		return "", errors.New("unable to marshal client session state to JSON: %v", err)
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

package tlsresumption

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/errors"
	"github.com/getlantern/keyman"
	utls "github.com/refraction-networking/utls"

	"github.com/stretchr/testify/assert"
)

var (
	sessionTicketKey = makeSessionTicketKey()

	text = []byte("Hello World")
)

func makeSessionTicketKey() [32]byte {
	var b [32]byte
	rand.Read(b[:])
	return b
}

func TestMakeClientSecrets(t *testing.T) {
	pk, err := keyman.GeneratePK(2048)
	if !assert.NoError(t, err) {
		return
	}

	cert, err := pk.TLSCertificateFor(time.Now().Add(1*time.Hour), true, nil, "tlsresumptiontest", "localhost")
	if !assert.NoError(t, err) {
		return
	}

	log.Debug("Getting session state from a temporary server")
	ss, err := getSessionState(pk, cert)
	if !assert.NoError(t, err) {
		return
	}

	log.Debug("Starting actual server")
	addr := "localhost:0"
	l, err := listenTLS(pk, cert, addr)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	// Now we can spawn multiple clients that reuse the existing session
	numClients := 2
	var wg sync.WaitGroup
	wg.Add(numClients)
	for i := 0; i < numClients; i++ {
		go func() {
			defer wg.Done()
			log.Debugf("Dialing %v", l.Addr().String())
			cache := utls.NewLRUClientSessionCache(1)
			conn, err := dialUTLS(cache, ss, l.Addr().String())
			if !assert.NoError(t, err) {
				return
			}
			css, ok := cache.Get(l.Addr().String())
			if !assert.True(t, ok) {
				return
			}
			defer conn.Close()
			assert.EqualValues(t, ss.MasterSecret(), css.MasterSecret(), "New connection should reuse client session state")
			assert.True(t, conn.ConnectionState().DidResume, "New connection should resume")
			_, err = conn.Write(text)
			if !assert.NoError(t, err) {
				return
			}
			b := make([]byte, len(text))
			_, err = io.ReadFull(conn, b)
			if !assert.NoError(t, err) {
				return
			}
			log.Debugf("Read: %v", string(b))
		}()
	}

	wg.Wait()
}

func getSessionState(pk *keyman.PrivateKey, cert *keyman.Certificate) (*utls.ClientSessionState, error) {
	// Listen on random port
	l, err := listenTLS(pk, cert, "localhost:0")
	if err != nil {
		return nil, errors.New("Unable to listen on random port: %v", err)
	}
	defer l.Close()

	ssStrings, err := MakeClientSessionStates(l.Addr().String(), 1)
	if err != nil {
		return nil, err
	}

	return ParseClientSessionState(ssStrings[0])
}

func listenTLS(pk *keyman.PrivateKey, cert *keyman.Certificate, addr string) (net.Listener, error) {
	kp, err := tls.X509KeyPair(cert.PEMEncoded(), pk.PEMEncoded())
	if err != nil {
		return nil, err
	}

	l, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates:     []tls.Certificate{kp},
		SessionTicketKey: sessionTicketKey,
		MaxVersion:       tls.VersionTLS12,
	})

	if err == nil {
		go func() {
			for {
				conn, err := l.Accept()
				if err == nil {
					go func() {
						io.Copy(conn, conn)
					}()
				}
			}
		}()
	}

	return l, err
}

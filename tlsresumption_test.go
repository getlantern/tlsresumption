package tlsresumption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/errors"
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
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	//pk, err := keyman.GeneratePK(2048)
	if !assert.NoError(t, err) {
		return
	}

	//cert, err := pk.TLSCertificateFor(time.Now().Add(1*time.Hour), true, nil, "tlsresumptiontest", "localhost")
	cert, err := tlsCertificateFor(pk, time.Now().Add(1*time.Hour), true, nil, "tlsresumptiontest", "localhost")
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

func getSessionState(pk *rsa.PrivateKey, cert *x509.Certificate) (*utls.ClientSessionState, error) {
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

func listenTLS(pk *rsa.PrivateKey, cert *x509.Certificate, addr string) (net.Listener, error) {
	// Generate a tls.X509KeyPair key pair from the private key and certificate
	// First generate a PEM encoded version of the cert and key
	certPEM := pemEncodeCertificate(cert)
	keyPEM := pemEncodePrivateKey(pk)

	kp, err := tls.X509KeyPair(certPEM, keyPEM)
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

func pemEncodeCertificate(cert *x509.Certificate) []byte {
	// 1. Create a PEM block using the certificate's Raw DER bytes
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	// 2. Encode the block to a byte slice
	return pem.EncodeToMemory(pemBlock)
}

func pemEncodePrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(pemBlock(key))
}

func tlsCertificateFor(key *rsa.PrivateKey,
	validUntil time.Time,
	isCA bool,
	issuer *x509.Certificate,
	organization string,
	commonName string,
	hosts ...string) (*x509.Certificate, error) {

	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(int64(time.Now().UnixNano())),
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   commonName,
		},
		NotBefore: time.Now().AddDate(0, -1, 0),
		NotAfter:  validUntil,

		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	if len(hosts) == 0 {
		hosts = []string{commonName}
	}

	for _, host := range hosts {
		// If host is an ip address, add it as an IP SAN
		ip := net.ParseIP(host)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	isSelfSigned := issuer == nil
	if isSelfSigned {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	// If it's a CA, add certificate signing
	if isCA {
		template.KeyUsage = template.KeyUsage | x509.KeyUsageCertSign
		template.IsCA = true
	}

	return certificateForKey(key, template, issuer, &key.PublicKey)
}

func certificateForKey(key *rsa.PrivateKey, template *x509.Certificate, issuerCert *x509.Certificate, publicKey interface{}) (*x509.Certificate, error) {
	if issuerCert == nil {
		// Note - for self-signed certificates, we include the host's external IP address
		issuerCert = template
	}
	derBytes, err := x509.CreateCertificate(
		rand.Reader, // secure entropy
		template,    // the template for the new cert
		issuerCert,  // cert that's signing this cert
		publicKey,   // public key
		key,         // private key
	)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

func pemBlock(key *rsa.PrivateKey) *pem.Block {
	return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
}

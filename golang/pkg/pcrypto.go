package pcrypto

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	openssl "github.com/Luzifer/go-openssl/v4"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

const (
	ProcyonProdRootCert = `-----BEGIN CERTIFICATE-----
MIICEDCCAbegAwIBAgIUYWwbXbqz7fK4FCmCVentPBT9Xs4wCgYIKoZIzj0EAwIw
VjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRAwDgYDVQQKEwdQcm9jeW9uMQ4w
DAYDVQQLEwVJbmZyYTEYMBYGA1UEAxMPUHJvY3lvbiBSb290IENBMB4XDTIyMDEz
MTIyMjIwNFoXDTQyMDEyNjIyMjIzNFowVjELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
AkNBMRAwDgYDVQQKEwdQcm9jeW9uMQ4wDAYDVQQLEwVJbmZyYTEYMBYGA1UEAxMP
UHJvY3lvbiBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0aQ+Ja2R
jumBUOdFWnfkki/nJ/JJEyvun7oxpqauI5FUDZMALL1AU7G3haWb3RaT9JBFZGI6
Ja/LwQpnC8UgS6NjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFJNn0hZrreT8cQb2ne1irDGoDjRyMB8GA1UdIwQYMBaAFJNn0hZr
reT8cQb2ne1irDGoDjRyMAoGCCqGSM49BAMCA0cAMEQCIHhMR7FvDj9XBPmfYao7
A2KwzxSGdPFP7bU/ZswHn4qDAiBSy1gReKVbbm8V5SC0lD/W5MfjViS79Hy6F8x3
RWwdhw==
-----END CERTIFICATE-----`
)

const (
	defaultKeepAliveInterval = time.Second * 30
	defaultKeepAliveTimeout  = time.Minute * 2
	GrpcMaxMessageSize       = 1024 * 1024 * 1024 * 4
)

// OpenSSLEncrypt - encrypt aes-256-cbc with SHA256
func OpenSSLEncrypt(plaintext string, passphrase string) (string, error) {
	o := openssl.New()

	enc, err := o.EncryptBytes(passphrase, []byte(plaintext), openssl.PBKDF2SHA256)
	if err != nil {
		logrus.Infof("An error occurred: %s\n", err)
		return "", err
	}

	return string(enc), nil
}

// OpenSSLDecrypt - decrypt aes-256-cbc with SHA256
// run: openssl aes-256-cbc -d -a -pbkdf2 -in encrData.txt -out clearData.txt
func OpenSSLDecrypt(opensslEncrypted string, passphrase string) (string, error) {
	o := openssl.New()

	dec, err := o.DecryptBytes(passphrase, []byte(opensslEncrypted), openssl.PBKDF2SHA256)
	if err != nil {
		logrus.Infof("An error occurred: %s\n", err)
		return "", err
	}

	return string(dec), nil
}

// NewExternalClient creates external GRPC client to talk to controller
func NewExternalClient(localName, remoteName string) (*grpc.ClientConn, error) {
	certPool := x509.NewCertPool()
	tlsConfig := tls.Config{
		RootCAs:               certPool,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: customServerVerify,
	}

	ok := certPool.AppendCertsFromPEM([]byte(ProcyonProdRootCert))
	if !ok {
		return nil, fmt.Errorf("Prod Root CA load failed")
	}

	tlsConfig.RootCAs = certPool

	// connect to server
	kplv := grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: defaultKeepAliveInterval, Timeout: defaultKeepAliveTimeout})
	creds := credentials.NewTLS(&tlsConfig)
	var conn *grpc.ClientConn
	var err error
	conn, err = grpc.Dial(remoteName, grpc.WithTransportCredentials(creds), grpc.WithBlock(), kplv,
		grpc.WithMaxMsgSize(GrpcMaxMessageSize),
		grpc.WithTimeout(time.Minute))
	if err != nil {
		logrus.Errorf("Error connecting to the server %s. Err: %v", remoteName, err)
		return nil, err
	}

	return conn, nil
}

func customServerVerify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// 0 - containts server cert
	// 1 - contains the root - we will not use it and replace with constants.ProcyonRootCert & constants.ProcyonProdRootCert
	// 2+ - contains intermediate certs

	serverCert, _ := x509.ParseCertificate(rawCerts[0])

	rootPool := x509.NewCertPool()

	ok := rootPool.AppendCertsFromPEM([]byte(ProcyonProdRootCert))
	if !ok {
		return fmt.Errorf("Prod Root CA load failed")
	}

	interCerts := rawCerts[2:]
	interPool := x509.NewCertPool()
	for _, intR := range interCerts {
		cert, _ := x509.ParseCertificate(intR)
		interPool.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certChains, err := serverCert.Verify(opts)
	if err != nil {
		logrus.Infof("Server Certchain verify failed: %v", err)
		return err
	}
	if len(certChains) != 1 {
		return errors.New("ServerCertError: Must match one chain")
	}

	return nil
}

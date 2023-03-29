package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"

	rpc "github.com/procyonai/targetcert/golang/generated"
	pcrypto "github.com/procyonai/targetcert/golang/pkg"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/util/keyutil"
)

// proxy cert related constants
var (
	ProxyTokenFile = "proxy-token.data"
	ProxyCertFile  = "proxy-crt.pem"
	ProxyCaFile    = "proxy-ca.pem"
	ProxyKeyFile   = "proxy-key.pem"
)

func main() {
	logrus.Infof("**** CertUtil Example ***")

	apikey := flag.String("apikey", "", "Tenant API Key")
	apisecret := flag.String("apisecret", "", "Tenant API Secret")
	clusterid := flag.String("clusterid", "", "ClusterID for Appliance")
	cntrlurl := flag.String("cntrlurl", "", "cntrlURL for getting cert")
	certpath := flag.String("certpath", "", "optional - write test cert/keys to this path")
	flag.Parse()

	if len(*apikey) == 0 {
		logrus.Infof("apikey can't be empty: %s", *apikey)
		return
	}

	if len(*apisecret) == 0 {
		logrus.Infof("apisecret can't be empty: %s", *apisecret)
		return
	}

	if len(*clusterid) == 0 {
		logrus.Infof("clusterid can't be empty: %s", *clusterid)
		return
	}

	if len(*cntrlurl) == 0 {
		logrus.Infof("cntrlurl can't be empty: %s", *cntrlurl)
		return
	}

	//This is what will be done inside  appliance - privateKey will never leave the appliance
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logrus.Infof("failed to generte Private Key")
		return
	}

	pemkey, err := keyutil.MarshalPrivateKeyToPEM(privateKey)
	if err != nil {
		logrus.Infof("failed to marshal Private Key")
		return
	}
	ProxyKey := string(pemkey)

	//CSR will be generated inside applaince as well
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "doesn't matter",
			Country:            []string{"US"},
			Province:           []string{"CA"},
			Organization:       []string{"doesn't matter"},
			OrganizationalUnit: []string{"doesn't matter"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		logrus.Infof("failed to generte CSR")
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	logrus.Infof("CSR: %s", csrPEM)
	token := *apisecret
	encCsr, err := pcrypto.OpenSSLEncrypt(string(csrPEM), token)
	if err != nil {
		logrus.Infof("failed to encrypting CSR")
		return
	}
	logrus.Infof("Encrypted CSR: %s", encCsr)

	targetCertReq := rpc.TargetCertReq{
		APIKey:    *apikey,
		EncCSR:    encCsr,
		ClusterID: *clusterid,
	}

	grclient, err := pcrypto.NewExternalClient("certutil", *cntrlurl)
	if err != nil {
		logrus.Infof("failed to establish grpc connection: %+v", err)
		return
	}

	notaryOpenClient := rpc.NewNotaryOpenServiceClient(grclient)
	targetCertResp, err := notaryOpenClient.GenTargetCert(context.Background(), &targetCertReq)
	if err != nil {
		logrus.Infof("failed to generting certificate")
		return
	}
	logrus.Infof("Generated Cert: %s", targetCertResp.Cert)
	logrus.Infof("Generated CertChain: %s", targetCertResp.CertChain)
	logrus.Infof("Generated Token: %s", targetCertResp.Token)

	/*
		Write generated content to following files:
		original privatekey to CERT_FOLDER/proxy-key.pem
		targetCertResp.Cert to CERT_FOLDER/proxy-crt.pem
		targetCertResp.CertChain to CERT_FOLDER/proxy-ca.pem
		targetCertResp.Token to CERT_FOLDER/proxy-token.data
	*/

	// proxy cert related constants

	if len(*certpath) != 0 {
		_, err = os.Stat(*certpath)
		ProxyTokenPath := filepath.Join(*certpath, ProxyTokenFile)
		ProxyCertPath := filepath.Join(*certpath, ProxyCertFile)
		ProxyKeyPath := filepath.Join(*certpath, ProxyKeyFile)
		ProxyCaPath := filepath.Join(*certpath, ProxyCaFile)

		if err == nil {
			logrus.Infof("%s exists - writing cert/key/cacert", *certpath)
			err = ioutil.WriteFile(ProxyCertPath, []byte(targetCertResp.Cert), 0755)
			if err != nil {
				logrus.Infof("Cert write to %s failed", ProxyCertPath)
				return
			}
			err = ioutil.WriteFile(ProxyKeyPath, []byte(ProxyKey), 0755)
			if err != nil {
				logrus.Infof("Key write to %s failed", ProxyKeyPath)
				return
			}
			err = ioutil.WriteFile(ProxyCaPath, []byte(targetCertResp.CertChain), 0755)
			if err != nil {
				logrus.Infof("CA Cert write to %s failed", ProxyCaPath)
				return
			}
			err = ioutil.WriteFile(ProxyTokenPath, []byte(targetCertResp.Token), 0755)
			if err != nil {
				logrus.Infof("ProxyToken write to %s failed", ProxyTokenPath)
				return
			}
		}
	}
}

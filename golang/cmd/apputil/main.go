package main

import (
	"context"
	"encoding/json"
	"flag"

	rpc "github.com/procyonai/targetcert/golang/generated"
	pcrypto "github.com/procyonai/targetcert/golang/pkg"
	"github.com/sirupsen/logrus"
)

// AppReqData stores request
type AppReqData struct {
	AppName           string `json:"appname"`
	Org               string `json:"org"`
	FrontendURLPrefix string `json:"frontend_url_prefix"`
	BackendURL        string `json:"backend_url"`
	MeshCluster       string `json:"mesh_cluster"`
}

func main() {
	logrus.Infof("**** AppUtil Example ***")

	apikey := flag.String("apikey", "", "Tenant API Key")
	apisecret := flag.String("apisecret", "", "Tenant API Secret")
	appname := flag.String("appname", "", "Application Appname")
	fronturl := flag.String("fronturl", "", "Front End URL Prefix")
	backurl := flag.String("backurl", "", "Back End URL")
	meshcluster := flag.String("meshcluster", "", "Mesh Cluster Name")
	cntrlurl := flag.String("cntrlurl", "app-nginx.proxyon.cloud:443", "cntrlURL for getting cert")
	org := flag.String("org", "default", "Optional - in case of multi org")
	flag.Parse()

	if len(*apikey) == 0 {
		logrus.Infof("apikey can't be empty: %s", *apikey)
		return
	}

	if len(*apisecret) == 0 {
		logrus.Infof("apisecret can't be empty: %s", *apisecret)
		return
	}

	if len(*appname) == 0 {
		logrus.Infof("appname can't be empty: %s", *appname)
		return
	}

	if len(*fronturl) == 0 {
		logrus.Infof("fronturl can't be empty: %s", *fronturl)
		return
	}

	if len(*backurl) == 0 {
		logrus.Infof("backurl can't be empty: %s", *backurl)
		return
	}

	if len(*meshcluster) == 0 {
		logrus.Infof("meshcluster can't be empty: %s", *meshcluster)
		return
	}

	if len(*cntrlurl) == 0 {
		logrus.Infof("cntrlurl can't be empty: %s", *cntrlurl)
		return
	}

	clreeq := AppReqData{
		AppName:           *appname,
		FrontendURLPrefix: *fronturl,
		BackendURL:        *backurl,
		MeshCluster:       *meshcluster,
		Org:               *org,
	}

	jdata, err := json.Marshal(clreeq)
	if err != nil {
		logrus.Infof("failed to marsgak requst")
		return
	}

	token := *apisecret
	encdata, err := pcrypto.OpenSSLEncrypt(string(jdata), token)
	if err != nil {
		logrus.Infof("failed to encrypting request")
		return
	}

	appCreateReq := rpc.AppCreateReq{
		APIKey:     *apikey,
		EncReqData: encdata,
	}

	grclient, err := pcrypto.NewExternalClient("certutil", *cntrlurl)
	if err != nil {
		logrus.Infof("failed to establish grpc connection: %+v", err)
		return
	}

	notaryOpenClient := rpc.NewNotaryOpenServiceClient(grclient)
	appCreateResp, err := notaryOpenClient.CreateApplication(context.Background(), &appCreateReq)
	if err != nil {
		logrus.Infof("failed to create application")
		return
	}
	logrus.Infof("Created AppName: %s", appCreateResp.AppName)
	logrus.Infof("Created AppURL: %s", appCreateResp.AppURL)
}

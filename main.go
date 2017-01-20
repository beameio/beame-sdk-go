// Steve Phillips / elimisteve
// 2017.01.18

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	homedir "github.com/mitchellh/go-homedir"
)

var (
	endpoint = "https://ieoateielwkqnbuw.tl5h1ipgobrdqsj6.v1.p.beameio.net"

	registerSuffix = "/api/v1/node/register"
)

func main() {
	var fqdn string
	flag.StringVar(&fqdn, "fqdn", "", "FQDN of client cert to use")
	flag.Parse()

	client, err := Client(fqdn)
	if err != nil {
		log.Fatal(err)
	}

	registerURL := endpoint + registerSuffix

	// Empty POST body
	resp, err := client.Post(registerURL, "application/json", nil)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Response: %s\n", body)

	// Find parent cred
}

// Client returns an HTTP client that uses the client cert for the
// given FQDN
func Client(fqdn string) (*http.Client, error) {
	prefix, err := homedir.Expand("~/.beame/v2/" + fqdn)
	if err != nil {
		return nil, fmt.Errorf("Error expanding fqdn cert path: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(prefix+"/x509.pem",
		prefix+"/private_key.pem")
	if err != nil {
		return nil, err
	}

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates:  []tls.Certificate{cert},
		Renegotiation: tls.RenegotiateFreelyAsClient,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	return client, nil
}

// RegisterPost represents the payload POSTed to the Beame server to
// register a new device. (The response is a ...)
type TokenRegisterPost struct {
}

type Cred struct {
}

type Metadata struct {
	ParentFqdn   string `json:"parent_fqdn"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	ServiceName  string `json:"serviceName"`
	ServiceId    string `json:"serviceId"`
	MatchingFqdn string `json:"matchingFqdn"`
	Src          string `json:"src"`
}

type AuthTokenMap struct {
	Auth struct {
		Name       string     `json:"name"`
		Email      string     `json:"email"`
		Type       string     `json:"type"`
		SignedData SignedData `json:"signedData"`
	}
}

type SignedData struct {
	CreatedAt string `json:"created_at"`
	ValidTill string `json:"valid_till"`
	Data      string `json:"data"`
	SignedBy  string `json:"signed_by"`
	Signature string `json:"signature"`
}

// CA_Pool := x509.NewCertPool()
// severCert, err := ioutil.ReadFile(
// 	"ca.pem")
// if err != nil {
// 	log.Fatal("Could not load server certificate!")
// }
// CA_Pool.AppendCertsFromPEM(severCert)

// config := tls.Config{RootCAs: CA_Pool}

// conn, err := tls.Dial("tcp", "127.0.0.1:8000", &config)
// if err != nil {
// 	log.Fatalf("client: dial: %s", err)
// }

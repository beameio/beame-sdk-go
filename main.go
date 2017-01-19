// Steve Phillips / elimisteve
// 2017.01.18

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	pathPrefix = "/home/steve/.beame/v2/ptxwfwqz364tp0wq.v1.p.beameio.net/"
	endpoint   = "https://ieoateielwkqnbuw.tl5h1ipgobrdqsj6.v1.p.beameio.net"

	register = endpoint + "/api/v1/node/register"
)

func main() {
	client, err := Client()
	if err != nil {
		log.Fatal(err)
	}

	resp, err := client.Get(endpoint)
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

// Connect to HTTPS server using client cert
func Client() (*http.Client, error) {
	// Load client cert
	cert, err := tls.LoadX509KeyPair("selfsigned.crt", "selfsigned.key")
	if err != nil {
		return nil, err
	}

	// Load CA cert
	caCert, err := ioutil.ReadFile("../secure-server/selfsigned.crt")
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Setup HTTPS client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	return client, nil
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

// Steve Phillips / elimisteve
// 2017.01.18

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	homedir "github.com/mitchellh/go-homedir"
)

var (
	// BaseURL    = "https://ieoateielwkqnbuw.tl5h1ipgobrdqsj6.v1.p.beameio.net"
	// BaseDNSURL = "https://lcram0sj9ox726l1.tl5h1ipgobrdqsj6.v1.p.beameio.net"
	BaseURL    = "https://prov-staging.beameio.net"
	BaseDNSURL = "https://t24w58ow5jkkmkhu.mpk3nobb568nycf5.v1.d.beameio.net"

	loadBalancerEndpoint = "https://may129m153e6emrn.bqnp2d2beqol13qn.v1.d.beameio.net/instance"

	registerSuffix         = "/api/v1/node/register"
	registerCompleteSuffix = "/api/v1/node/register/complete"
	getDnsSuffix           = "/v1/dns/host/"
)

func main() {
	var fqdn string
	flag.StringVar(&fqdn, "fqdn", "", "FQDN of client cert to use")

	var email string
	flag.StringVar(&email, "email", "", "Email to be tied to new cert")

	flag.Parse()

	beameV2dir, _ := homedir.Expand("~/.beame/v2")

	fqdnDir := beameV2dir + "/" + fqdn

	log.Printf("fqdnDir == %v\n", fqdnDir)

	client, err := Client(fqdnDir)
	if err != nil {
		log.Fatalf("Error creating client: %v\n", err)
	}

	// Register new "token" (returns new FQDN)

	registerURL := BaseURL + registerSuffix
	jsonb, _ := json.Marshal(TokenRegisterPost{ParentFqdn: fqdn, Email: email})

	resp, err := client.Post(registerURL, "application/json",
		bytes.NewReader(jsonb))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Response from %s: `%s`\n", registerURL, body)

	var metadata Metadata
	err = json.Unmarshal(body, &metadata)
	if err != nil {
		log.Fatal(err)
	}

	// Registered, which gave us our new domain that will point to the
	// new device we're provisioning, which is a subdomain of `fqdn`
	// as specified above

	// Now we have to generate a CSR

	newFqdn := metadata.Fqdn
	newFD := beameV2dir + "/" + newFqdn

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating RSA key: %v", err)
	}

	csrb, err := genCSR(rsaKey, newFqdn, email)
	if err != nil {
		log.Fatalf("Error generating CSR: %v", err)
	}

	// Save private RSA key
	_ = os.Mkdir(newFD, 0700)
	err = ioutil.WriteFile(newFD+"/private_key.pem",
		x509.MarshalPKCS1PrivateKey(rsaKey), 0600)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Generated new CSR:\n%s\n", csrb)

	pubb, err := ioutil.ReadFile(fqdnDir + "/public_key.pem")
	if err != nil {
		log.Fatal(err)
	}

	pubbkb, err := ioutil.ReadFile(fqdnDir + "/public_key_bk.pem")
	if err != nil {
		log.Fatal(err)
	}

	regComplete := &RegisterComplete{
		CSR:      string(csrb),
		Validity: 86400 * 180, // 180 days
		Pub: Pub{
			Pub:       string(pubb),
			PubBk:     string(pubbkb),
			Signature: "", // TODO
		},
		Format: 1,
		Fqdn:   newFqdn,
	}

	regCompleteb, _ := json.Marshal(regComplete)
	registerCompleteURL := BaseURL + registerCompleteSuffix

	resp2, err := client.Post(registerCompleteURL, "application/json",
		bytes.NewReader(regCompleteb))
	if err != nil {
		log.Fatal(err)
	}
	defer resp2.Body.Close()

	body, _ = ioutil.ReadAll(resp2.Body)

	log.Printf("Response from %s: `%s`\n", registerCompleteURL, body)

	var cert Certificate
	err = json.Unmarshal(body, &cert)
	if err != nil {
		log.Fatal(err)
	}

	// Got new cert. Save to disk.

	err = cert.SaveTo(newFD)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("New cert created, tied to new domain: %s\n", newFD)

	// Figure out which edge server I'm closest to

	resp3, err := http.Get(loadBalancerEndpoint)
	if err != nil {
		log.Fatal(err)
	}
	defer resp3.Body.Close()

	body, _ = ioutil.ReadAll(resp3.Body)

	log.Printf("Response from %v: `%s`\n", loadBalancerEndpoint, body)

	var lb Instance
	err = json.Unmarshal(body, &lb)
	if err != nil {
		log.Fatal(err)
	}

	edgeFqdn := lb.InstanceData.Endpoint

	metadata.EdgeFqdn = edgeFqdn
	metadata.Email = email

	// Save metadata.json
	err = metadata.SaveTo(newFD)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("edgeFqdn: %s\n", edgeFqdn)

	// Create token to send to server to point

	signedData := &SignedData{
		CreatedAt: time.Now().Unix(),
		ValidTill: time.Now().Unix() + int64(86400), // 1 day
		Data:      map[string]string{"fqdn": newFqdn, "value": edgeFqdn},
	}

	tokenb, _ := json.Marshal(signedData)

	hashed := sha1.Sum(tokenb)

	signedToken, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA1,
		hashed[:])
	if err != nil {
		log.Fatalf("Error from rsaKey.Sign: %v\n", err)
	}

	postURL := BaseDNSURL + getDnsSuffix + newFqdn

	regFqdnDns := RegisterFqdnDns{
		SignedData: signedData,
		SignedBy:   newFqdn,
		Signature:  signedToken,
	}

	post := map[string]interface{}{"authToken": regFqdnDns}

	postdata, _ := json.Marshal(post)

	log.Printf("POSTing the following to %s: `%s`\n", postURL, postdata)

	req, _ := http.NewRequest("POST", postURL,
		bytes.NewReader(postdata))

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// req.Header.Set("X-BeameAuthToken", authTokenStr)

	// Tell Beame's edgeFqdn to point newFqdn to my machine

	resp4, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp4.Body.Close()

	body, _ = ioutil.ReadAll(resp4.Body)

	log.Printf("Response from %s: `%s`\n", postURL, body)
}

// Client returns an HTTP client that uses the client cert for the
// given FQDN
func Client(fqdnDir string) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(fqdnDir+"/x509.pem",
		fqdnDir+"/private_key.pem")
	if err != nil {
		return nil, fmt.Errorf("Error from tls.LoadX509KeyPair: %v", err)
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
	ParentFqdn string `json:"parent_fqdn"`
	Email      string `json:"email,omitempty"`
	EdgeFqdn   string `json:"edge_fqdn,omitempty"`
	IP         string `json:"ip,omitempty"`
	Agree      bool   `json:"agree,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
	Src        int    `json:"src,omitempty"`
	Name       string `json:"name,omitempty"`
}

type Metadata struct {
	// Populated by response from /register
	ID         string `json:"$id"`
	ParentFqdn string `json:"parent_fqdn"`
	Fqdn       string `json:"fqdn"`
	Level      int    `json:"level"`

	// Populated manually
	LocalIP  string `json:"local_ip"`
	EdgeFqdn string `json:"edge_fqdn"`
	Name     string `json:"name"`
	Email    string `json:"email"`
}

func (m *Metadata) SaveTo(newFD string) error {
	err := os.Mkdir(newFD, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	jsonb, err := json.Marshal(m)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(newFD+"/metadata.json", jsonb, 0600)
	if err != nil {
		return err
	}

	return nil
}

type Certificate struct {
	ID    string `json:"$id"`
	X509  string `json:"x509"`
	Pkcs7 string `json:"pkcs7"`
	CA    string `json:"ca"`
}

func (cert *Certificate) SaveTo(newFD string) error {
	err := os.Mkdir(newFD, 0700)
	if err != nil && !os.IsExist(err) {
		return err
	}

	err = ioutil.WriteFile(newFD+"/x509.pem", []byte(cert.X509), 0600)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(newFD+"/pkcs7.pem", []byte(cert.Pkcs7), 0600)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(newFD+"/ca.pem", []byte(cert.CA), 0600)
	if err != nil {
		return err
	}

	return nil
}

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func genCSR(rsaKey *rsa.PrivateKey, fqdn, email string) ([]byte, error) {
	subj := pkix.Name{
		CommonName:         fqdn,
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"CrypTag"},
		OrganizationalUnit: []string{"IT"},
	}
	rawSubj := subj.ToRDNSequence()
	rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
		{Type: oidEmailAddress, Value: email},
	})

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		return nil, err
	}

	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		EmailAddresses:     []string{email},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	var buf bytes.Buffer
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, rsaKey)
	if err != nil {
		return nil, err
	}

	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type RegisterComplete struct {
	CSR      string `json:"csr"`
	Validity int    `json:"validity"`
	Pub      Pub    `json:"pub"`
	Format   int    `json:"format"`
	Fqdn     string `json:"fqdn"`
}

type Pub struct {
	Pub       string `json:"pub"`
	PubBk     string `json:"pub_bk"`
	Signature string `json:"signature"`
}

type Instance struct {
	InstanceData InstanceData `json:"instanceData"`
}

type InstanceData struct {
	AMIID          string `json:"amiid"`
	InstanceID     string `json:"instanceid"`
	AvlZone        string `json:"avlZone"`
	LocalIPv4      string `json:"localipv4"`
	PublicHostname string `json:"publichostname"`
	PublicIPv4     string `json:"publicipv4"`
	Endpoint       string `json:"endpoint"`
}

type RegisterFqdnDns struct {
	SignedData *SignedData `json:"signedData"`
	SignedBy   string      `json:"signedBy"`
	Signature  []byte      `json:"signature"`
}

type SignedData struct {
	CreatedAt int64             `json:"created_at"`
	ValidTill int64             `json:"valid_till"`
	Data      map[string]string `json:"data"`
}

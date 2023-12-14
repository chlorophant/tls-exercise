package main

import (
	// "os"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"
)

var certCache = map[string]tls.Certificate{}
var caRootCert *x509.Certificate
var caRootPrivKey *rsa.PrivateKey
var caIntermediateCert *x509.Certificate
var caIntermediatePrivKey *rsa.PrivateKey

func createRootCa() (err error) {
	// configure our CA root certificate
	caRootCert = &x509.Certificate{
		SerialNumber: big.NewInt(9001),
		Subject: pkix.Name{
			CommonName: "Cory's Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 year expiration
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caRootPrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	// // create the CA root cert
	// caRootBytes, err := x509.CreateCertificate(rand.Reader, caRootCert, caRootCert, &caRootPrivKey.PublicKey, caRootPrivKey)
	// if err != nil {
	// 	panic(err)
	// }

	// // pem encode
	// caRootPrivKeyPEM := new(bytes.Buffer)
	// pem.Encode(caRootPrivKeyPEM, &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(caRootPrivKey),
	// })

	// caRootPEM := new(bytes.Buffer)
	// pem.Encode(caRootPEM, &pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: caRootBytes,
	// })

	// // Write to files for debugging
	// privateRootKeyFile, err := os.Create("ca_root_private_key.pem")
	// if err != nil {
	//     log.Println("Error creating private key file")
	//     os.Exit(1)
	// }
	// pem.Encode(privateRootKeyFile, &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(caRootPrivKey),
	// })
	// privateRootKeyFile.Close()
	// publicRootKeyFile, err := os.Create("ca_root_public_key.pem")
	// if err != nil {
	//     log.Println("Error creating public key file")
	//     os.Exit(1)
	// }
	// pem.Encode(publicRootKeyFile, &pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: caRootBytes,
	// })
	// publicRootKeyFile.Close()

	return nil
}

func createIntermediateCa() (err error) {
	// configure our intermediate CA certificate
	caIntermediateCert = &x509.Certificate{
		SerialNumber: big.NewInt(9002),
		Subject: pkix.Name{
			CommonName: "Cory's Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0), // 2 year expiration
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caIntermediatePrivKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// // create the intermediate cert, signed by the ca root
	// caIntermediateBytes, err := x509.CreateCertificate(rand.Reader, caIntermediateCert, caRootCert, &caIntermediatePrivKey.PublicKey, caRootPrivKey)
	// if err != nil {
	// 	return err
	// }

	// // pem encode
	// caIntermediatePrivKeyPEM := new(bytes.Buffer)
	// pem.Encode(caIntermediatePrivKeyPEM, &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(caIntermediatePrivKey),
	// })

	// caIntermediatePEM := new(bytes.Buffer)
	// pem.Encode(caIntermediatePEM, &pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: caIntermediateBytes,
	// })

	// // Write to files for debugging
	// privateIntermediateKeyFile, err := os.Create("ca_intermediate_private_key.pem")
	// if err != nil {
	// 	log.Println("Error creating private key file")
	// 	os.Exit(1)
	// }
	// pem.Encode(privateIntermediateKeyFile, &pem.Block{
	// 	Type:  "RSA PRIVATE KEY",
	// 	Bytes: x509.MarshalPKCS1PrivateKey(caIntermediatePrivKey),
	// })
	// privateIntermediateKeyFile.Close()
	// publicIntermediateKeyFile, err := os.Create("ca_intermediate_public_key.pem")
	// if err != nil {
	// 	log.Println("Error creating public key file")
	// 	os.Exit(1)
	// }
	// pem.Encode(publicIntermediateKeyFile, &pem.Block{
	// 	Type:  "CERTIFICATE",
	// 	Bytes: caIntermediateBytes,
	// })
	// publicIntermediateKeyFile.Close()

	return nil
}

func getOrCreateDynamicCert(uri string) (tls.Certificate, error) {
	cert, hasCert := certCache[uri]

	log.Printf("Found cached cert: %t", hasCert)

	if !hasCert {
		// configure our dynamic certificate
		dynamicCert := &x509.Certificate{
			SerialNumber: big.NewInt(9003), //TODO: Make this random?
			Subject: pkix.Name{
				CommonName: "Dynamic Cert",
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(1, 0, 0), // 1 year expiration
			IsCA:        false,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature,
		}

		// create our private and public key
		dynamicCertPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Println("Error creating dynamicCertPrivKey")
			return tls.Certificate{}, err
		}

		// create the dynamic cert, signed by the intermediate ca
		dynamicCertBytes, err := x509.CreateCertificate(rand.Reader, dynamicCert, caIntermediateCert, &dynamicCertPrivKey.PublicKey, caIntermediatePrivKey)
		if err != nil {
			log.Println("Error creating dynamicCertBytes")
			return tls.Certificate{}, err
		}

		// pem encode
		dynamicCertPrivKeyPEM := new(bytes.Buffer)
		pem.Encode(dynamicCertPrivKeyPEM, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(dynamicCertPrivKey),
		})

		dynamicCertPEM := new(bytes.Buffer)
		pem.Encode(dynamicCertPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: dynamicCertBytes,
		})

		serverCert, err := tls.X509KeyPair(dynamicCertPEM.Bytes(), dynamicCertPrivKeyPEM.Bytes())
		if err != nil {
			log.Println("Error creating serverCert")
			return tls.Certificate{}, err
		}
		certCache[uri] = serverCert
		cert = serverCert
	}
	return cert, nil
}

func main() {
	err := createRootCa()
	if err != nil {
		log.Println("Error creating root ca cert")
		panic(err)
	}
	err = createIntermediateCa()
	if err != nil {
		log.Println("Error creating intermediate ca cert")
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		targetURI := "https://" + r.Host + r.URL.RequestURI()
		log.Printf("Called with %s", targetURI)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"status": "OK"}`)
	})

	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// See: https://pkg.go.dev/crypto/tls#ClientHelloInfo
				uri := clientHello.ServerName // This is not the full uri (would be "localhost" in this context)
				// log.Print(clientHello.Conn.RemoteAddr()) // This returns an IP
				cert, err := getOrCreateDynamicCert(uri)
				if err != nil {
					log.Println("Error getting or creating dynamic cert")
					return nil, err
				}
				return &cert, nil
			},
		},
	}

	err = server.ListenAndServeTLS("", "") // Empty params ignored, and are not needed due to previous serverTLSConf configuration
}

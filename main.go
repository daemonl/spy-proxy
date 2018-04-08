package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daemonl/proxy/certs"
	"gopkg.daemonl.com/envconf"
)

func main() {
	if err := envconf.Parse(&config); err != nil {
		log.Fatal(err.Error())
	}

	if err := do(); err != nil {
		log.Fatal(err.Error())
	}
}

var config struct {
	Bind string `env:"BIND" default:":8888"`
}

var certificateSet *certs.CertificateSet

func do() error {

	rootKey, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		return err
	}

	certificateSet, err = certs.NewCertificateSet(rootKey)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr: config.Bind,
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if req.URL.Host == "proxy" && req.URL.Path == "/ca.crt" {
				rw.Header().Add("Content-Type", "application/x-x509-ca-cert")
				http.ServeFile(rw, req, "cert.pem")
				return
			}

			if req.Method == http.MethodConnect {
				handleTunnel(rw, req)
			} else {
				handleHTTP(rw, req)
			}
		}),
	}

	return server.ListenAndServe()
}

func handleHTTP(rw http.ResponseWriter, req *http.Request) {
	log.Printf("HTTP Connection %s %s\n", req.Method, req.URL.String())

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Printf("Err: %s\n", err.Error())
		http.Error(rw, err.Error(), http.StatusServiceUnavailable)
	}

	defer resp.Body.Close()
	copyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		io.Copy(rw, resp.Body)
	}
	log.Printf("HTTP Connection %s %s %d\n", req.Method, req.URL.String(), resp.StatusCode)

}

func copyHeader(dest, src http.Header) {
	for k, vals := range src {
		for _, val := range vals {
			dest.Add(k, val)
		}
	}
}

func handleTunnel(w http.ResponseWriter, r *http.Request) {
	log.Printf("Tunnel Connection %s\n", r.Host)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Err: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}

	client_conn.Write([]byte("HTTP/1.1 200 OK\n\n"))

	if strings.HasSuffix(r.Host, "keno.com.au:443") {
		log.Println("Start Spy")
		if err := spy(client_conn, r); err != nil {
			log.Println(err.Error())
		}
		return
	}

	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Printf("Err: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()

	io.Copy(destination, source)
}

func spy(clientPlain net.Conn, connectRequest *http.Request) error {
	defer clientPlain.Close()

	serverCertificate, err := certificateSet.ForDomain(connectRequest.Host)
	if err != nil {
		return err
	}

	client := tls.Server(clientPlain, &tls.Config{
		Certificates: []tls.Certificate{*serverCertificate},
	})

	readerIn := bufio.NewReader(io.TeeReader(client, os.Stdout))

	req, err := http.ReadRequest(readerIn)
	if err != nil {
		return err
	}

	req.RequestURI = ""
	req.URL.Scheme = "https"
	req.URL.Host = connectRequest.Host
	req.Header.Del("Accept-Encoding")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	cWrite := io.MultiWriter(client, os.Stdout)
	fmt.Fprintf(cWrite, "%s %s\n", resp.Proto, resp.Status)
	for key, vals := range resp.Header {
		for _, val := range vals {
			fmt.Fprintf(cWrite, "%s: %s\n", key, val)
		}
	}
	fmt.Fprintf(cWrite, "\n")
	if resp.Body != nil {
		if IsPlain(resp.Header.Get("Content-Type")) {
			io.Copy(cWrite, resp.Body)
		} else {
			io.Copy(client, resp.Body)
		}
	}
	client.Close()
	log.Printf("HTTP %s %s -> %d\n", req.Method, req.URL.String(), resp.StatusCode)

	return nil

}

func IsPlain(mType string) bool {
	if mType == "" {
		return true
	}
	root, _, err := mime.ParseMediaType(mType)
	if err != nil {
		return false
	}

	return strings.HasPrefix(root, "text") || strings.HasSuffix(root, "json")

}

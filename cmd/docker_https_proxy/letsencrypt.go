package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

const certbotConfigDir = "/etc/letsencrypt/"
const certbotWebRootDir = "/tmp/letsencrypt/"

const certbotEmailEnvName = "LETSENCRYPT_EMAIL"
const certbotDryRunEnvName = "LETSENCRYPT_DRY_RUN"

type newCertRequest struct {
	domain     string
	altDomains []string
}

// LetsEncryptServer represents a Let's Encrypt validation master server
type LetsEncryptServer struct {
	email          string
	dryRun         bool
	webroot        string
	newCertChannel chan newCertRequest
	lastModified   time.Time
}

func lastModifiedNow() time.Time {
	t, _ := http.ParseTime(time.Now().Format(http.TimeFormat))
	return t
}

// NewLetsEncryptServer creates a new LetsEncryptServer instance
func NewLetsEncryptServer() *LetsEncryptServer {
	return &LetsEncryptServer{
		newCertChannel: make(chan newCertRequest),
		lastModified:   lastModifiedNow(),
	}
}

func (s *LetsEncryptServer) parseEnv() error {
	s.email = os.Getenv(certbotEmailEnvName)
	if s.email == "" {
		return fmt.Errorf("%s missing or empty", certbotEmailEnvName)
	}

	dryRunStr := os.Getenv(certbotDryRunEnvName)
	s.dryRun = dryRunStr == "1" || strings.ToLower(dryRunStr) == "on"

	return nil
}

func (s *LetsEncryptServer) newSslCert(domain string, altDomains []string) error {
	cmd := exec.Command(
		"certbot",
		"certonly",
		"--non-interactive",
		"--agree-tos",
		"--max-log-backups", "0",
		"--email", s.email,
		"--webroot",
		"--webroot-path", certbotWebRootDir,
		"--domain", domain,
	)
	for _, altDomain := range altDomains {
		cmd.Args = append(cmd.Args, "--domain", altDomain)
	}

	if s.dryRun {
		cmd.Args = append(cmd.Args, "--dry-run")
	}

	log.Printf("starting certbot: %v %v", cmd.Path, cmd.Args)
	output, err := cmd.CombinedOutput()
	if err == nil {
		s.lastModified = lastModifiedNow()
	}
	log.Println(cmd.ProcessState.Success(), string(output))
	return err
}

func (s *LetsEncryptServer) renewSslCerts() error {
	cmd := exec.Command(
		"certbot",
		"renew",
		"--non-interactive",
		"--agree-tos",
		"--max-log-backups", "0",
	)

	if s.dryRun {
		cmd.Args = append(cmd.Args, "--dry-run")
	}

	log.Printf("starting certbot: %v %v", cmd.Path, cmd.Args)
	output, err := cmd.CombinedOutput()
	if err == nil {
		s.lastModified = lastModifiedNow()
	}
	log.Println(cmd.ProcessState.Success(), string(output))
	return err
}

func (s *LetsEncryptServer) checkIfCertExists(domain string) (bool, error) {
	baseDir := path.Join(certbotConfigDir, "live", domain)
	if _, err := os.Stat(baseDir); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	certPath := path.Join(baseDir, "fullchain.pem")
	privateKeyPath := path.Join(baseDir, "privkey.pem")

	if _, err := os.Stat(certPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	if _, err := os.Stat(privateKeyPath); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (s *LetsEncryptServer) processNewCertRequests() {
	for req := range s.newCertChannel {
		log.Printf("new cert request %v", req.domain)
		if req.domain == "RENEW" {
			err := s.renewSslCerts()
			if err != nil {
				log.Printf("failed to renew certificates: %v", err)
				continue
			}
			continue
		}
		exists, err := s.checkIfCertExists(req.domain)
		if err != nil {
			log.Printf("failed to check if certificate for %s already exists: %v", req.domain, err)
			continue
		}
		if exists {
			log.Printf("certificate for %s already exists, skipping", req.domain)
			continue
		}
		err = s.newSslCert(req.domain, req.altDomains)
		if err != nil {
			log.Printf("failed to generate certificate for %s: %v", req.domain, err)
			continue
		}
		log.Printf("successfully generated certificate for %s", req.domain)
	}
}

func (s *LetsEncryptServer) handleDump(writer http.ResponseWriter, request *http.Request) {
	log.Printf("/dump request")

	ifModifiedSinceStr := request.Header.Get("If-Modified-Since")
	if ifModifiedSinceStr != "" {
		ifModifiedSince, err := http.ParseTime(ifModifiedSinceStr)
		if err != nil {
			log.Printf("failed to parse If-Modified-Since date %v: %v", ifModifiedSinceStr, err)
		} else {
			log.Printf("comparing If-Modified-Since %v %v", ifModifiedSince, s.lastModified)
			if !s.lastModified.After(ifModifiedSince) {
				writer.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}

	cmd := exec.Command("tar", "-c", "-C", certbotConfigDir, ".")
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		log.Printf("certbot dump failed: %v", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "application/tar")
	writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	writer.Header().Set("Last-Modified", s.lastModified.Format(http.TimeFormat))
	writer.WriteHeader(http.StatusOK)
	writer.Write(data)
}

func (s *LetsEncryptServer) handleNewCert(writer http.ResponseWriter, request *http.Request) {
	request.ParseForm()
	domain := request.Form.Get("domain")
	altDomains := request.Form["alt_domains"]
	log.Printf("/new-cert?%s request", request.Form.Encode())

	if domain == "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	exists, err := s.checkIfCertExists(domain)
	if err != nil {
		log.Printf("failed to check if certificate for %s already exists: %v", domain, err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	if exists {
		log.Printf("certificate for %s already exists, skipping", domain)
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("already exists"))
		return
	}

	var r newCertRequest
	r.domain = domain
	r.altDomains = altDomains
	s.newCertChannel <- r

	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte("ok"))
}

func (s *LetsEncryptServer) handleHealth(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte("ok"))
}

// Run the LetsEncryptServer
func (s *LetsEncryptServer) Run() error {
	err := s.parseEnv()
	if err != nil {
		return err
	}

	err = os.MkdirAll(certbotWebRootDir, 0755)
	if err != nil {
		return err
	}

	go s.processNewCertRequests()

	go func() {
		for {
			var r newCertRequest
			r.domain = "RENEW"
			s.newCertChannel <- r
			time.Sleep(1 * time.Hour)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/dump", s.handleDump)
	mux.HandleFunc("/new-cert", s.handleNewCert)
	mux.HandleFunc("/_health", s.handleHealth)
	mux.Handle("/.well-known/acme-challenge/", http.FileServer(http.Dir(certbotWebRootDir)))

	server := &http.Server{Addr: fmt.Sprintf(":%d", defaultLetsEncryptServerPort), Handler: mux}
	return server.ListenAndServe()
}

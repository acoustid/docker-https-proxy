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

// LetsEncryptServer represents a Let's Encrypt validation master server
type LetsEncryptServer struct {
	email          string
	dryRun         bool
	webroot        string
	newCertChannel chan string
	lastModified   time.Time
}

// NewLetsEncryptServer creates a new LetsEncryptServer instance
func NewLetsEncryptServer() *LetsEncryptServer {
	return &LetsEncryptServer{
		newCertChannel: make(chan string),
		lastModified:   time.Now(),
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

func (s *LetsEncryptServer) newSslCert(domain string) error {
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

	if s.dryRun {
		cmd.Args = append(cmd.Args, "--dry-run")
	}

	log.Printf("starting certbot: %v %v", cmd.Path, cmd.Args)
	output, err := cmd.CombinedOutput()
	if err == nil {
		s.lastModified = time.Now()
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

	log.Printf("starting certbot: %v %v", cmd.Path, cmd.Args)
	output, err := cmd.CombinedOutput()
	if err == nil {
		s.lastModified = time.Now()
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
	for domain := range s.newCertChannel {
		log.Printf("new cert request %v", domain)
		if domain == "RENEW" {
			err := s.renewSslCerts()
			if err != nil {
				log.Printf("failed to renew certificates: %v", err)
				continue
			}
			continue
		}
		if domain == "PING" {
			continue
		}
		exists, err := s.checkIfCertExists(domain)
		if err != nil {
			log.Printf("failed to check if certificate for %s already exists: %v", domain, err)
			continue
		}
		if exists {
			log.Printf("certificate for %s already exists, skipping", domain)
			continue
		}
		err = s.newSslCert(domain)
		if err != nil {
			log.Printf("failed to generate certificate for %s: %v", domain, err)
			continue
		}
		log.Printf("successfully generated certificate for %s", domain)
	}
}

func (s *LetsEncryptServer) handleDump(writer http.ResponseWriter, request *http.Request) {
	log.Printf("/dump request")

	ifModifiedSinceStr := request.Header.Get("If-Modified-Since")
	if ifModifiedSinceStr != "" {
		ifModifiedSince, err := http.ParseTime(ifModifiedSinceStr)
		if err == nil {
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
	log.Printf("/new-cert?domain=%s request", domain)

	if domain != "" {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	exists, err := s.checkIfCertExists(domain)
	if err != nil {
		log.Print("failed to check if certificate for %s already exists: %v", domain, err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	if exists {
		log.Print("certificate for %s already exists, skipping", domain)
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte("already exists"))
		return
	}

	s.newCertChannel <- domain

	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte("ok"))
	return
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
			s.newCertChannel <- "RENEW"
			time.Sleep(1 * time.Hour)
		}
	}()

	go func() {
		for {
			s.newCertChannel <- "PING"
			time.Sleep(10 * time.Second)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/dump", s.handleDump)
	mux.HandleFunc("/new-cert", s.handleNewCert)
	mux.Handle("/.well-known/acme-challenge/", http.FileServer(http.Dir(certbotWebRootDir)))

	server := &http.Server{Addr: fmt.Sprintf(":%d", letsEncryptServerPort), Handler: mux}
	return server.ListenAndServe()
}

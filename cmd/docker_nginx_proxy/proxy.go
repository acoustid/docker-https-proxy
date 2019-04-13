package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"syscall"
	"text/template"
	"time"
)

type siteInfo struct {
	Domain      string `json:"domain"`
	SSL         siteSSLInfo
	LetsEncrypt siteLetsEncryptInfo
	Backend     []siteBackendServerInfo `json:"backend"`
}

type siteSSLInfo struct {
	Certificate string
	PrivateKey  string
}

type siteLetsEncryptInfo struct {
	Master siteLetsEncryptServerInfo
}

type siteLetsEncryptServerInfo struct {
	Host string
	Port int
}

type siteBackendServerInfo struct {
	Host        string                     `json:"host"`
	Port        int                        `json:"port"`
	HealthCheck siteBackendHealthCheckInfo `json:"healthcheck"`
}

type siteBackendHealthCheckInfo struct {
	Path string `json:"path"`
}

const nginxSiteTempate = `
set ${{.Name}}_letsencrypt_server {{.LetsEncrypt.Master.Host}};
set ${{.Name}}_backend_server {{.Backend.Host}};

server {
	listen 80;
	listen [::]:80;

	server_name {{.Domain}};

	location /.well-known/acme-challenge {"
		proxy_pass http://${{.Name}}_letsencrypt_server:{{.LetsEncrypt.Master.Port}};
	}

	location / {
			return 302 https://$host$request_uri;
	}
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;

	server_name {{.Domain}};

	ssl_certificate {{.SSL.Certificate}};
	ssl_certificate_key {{.SSL.PrivateKey}};

	client_max_body_size 0;

	location /.well-known/acme-challenge {"
		proxy_pass http://${{.Name}}_letsencrypt_server:{{.LetsEncrypt.Master.Port}};
	}

	location / {
					proxy_pass http://${{.Name}}_backend_server:{{.Backend.Port}};
					proxy_set_header Host $http_host;
					proxy_set_header X-Real-IP $remote_addr;
					proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
					proxy_set_header X-Forwarded-Proto https;
					proxy_set_header X-Forwarded-Ssl on;
					proxy_read_timeout 3600;
					proxy_connect_timeout 300;
					proxy_redirect off;
					proxy_http_version 1.1;
	}
}
`

const letsEncryptServerPort = 12812

const nginxLetsEncryptConfigDir = "/etc/nginx/letsencrypt/"
const nginxMainConfFile = "/etc/nginx/nginx.conf"
const nginxSitesDir = "/etc/nginx/sites/"
const nginxSitesConf = "/etc/nginx/conf.d/50-sites.conf"

const snakeoilSslCert = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
const snakeoilSslPrivateKey = "/etc/ssl/private/ssl-cert-snakeoil.key"

type sslCertInfo struct {
	certPath       string
	privateKeyPath string
}

func checkIfPathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (i sslCertInfo) Validate() (bool, error) {
	certPathExists, err := checkIfPathExists(i.certPath)
	if err != nil {
		return false, err
	}
	privateKeyPathExists, err := checkIfPathExists(i.privateKeyPath)
	if err != nil {
		return false, err
	}
	return certPathExists && privateKeyPathExists, nil
}

// ProxyServer is a nginx-based load balancer / proxy.
type ProxyServer struct {
	exitCh                      chan bool
	nginxProcess                *os.Process
	nginxsiteTmpl               *template.Template
	sslCerts                    map[string]*sslCertInfo
	letsEncryptServerHost       string
	letsEncryptDataLastModified string
}

// NewProxyServer creates a new ProxyServer instance.
func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		exitCh:        make(chan bool),
		nginxsiteTmpl: template.Must(template.New("config").Parse(nginxSiteTempate)),
	}
}

func (p *ProxyServer) getSslCertPath(domain string) string {
	info := p.sslCerts[domain]
	if info == nil {
		return snakeoilSslCert
	}
	return info.certPath
}

func (p *ProxyServer) getSslPrivateKeyPath(domain string) string {
	info := p.sslCerts[domain]
	if info == nil {
		return snakeoilSslPrivateKey
	}
	return info.privateKeyPath
}

func (p *ProxyServer) loadSslCerts() error {
	sslCertDir := path.Join(nginxLetsEncryptConfigDir, "live")
	entries, err := ioutil.ReadDir(sslCertDir)
	if err != nil {
		if os.IsNotExist(err) {
			p.sslCerts = make(map[string]*sslCertInfo)
			return nil
		}
		return err
	}

	p.sslCerts = make(map[string]*sslCertInfo)
	for _, entry := range entries {
		if entry.IsDir() {
			domain := entry.Name()
			info := &sslCertInfo{
				certPath:       path.Join(sslCertDir, domain, "fullchain.pem"),
				privateKeyPath: path.Join(sslCertDir, domain, "privkey.pem"),
			}
			valid, err := info.Validate()
			if err != nil {
				return err
			}
			if valid {
				p.sslCerts[domain] = info
			}
		}
	}
	return nil
}

func (p *ProxyServer) updateNginxConfFiles() error {
	err := p.loadSslCerts()
	if err != nil {
		log.Printf("failed to load SSL certificates: %v", err)
		return err
	}

	files, err := ioutil.ReadDir(nginxSitesDir)
	if err != nil {
		return err
	}

	blockRe := regexp.MustCompile(`block=([^ ]+)`)
	domainRe := regexp.MustCompile(`domain=([^ ]+)`)

	var config strings.Builder

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		filename := path.Join(nginxSitesDir, file.Name())
		log.Printf("reading nginx config file %v", filename)
		data, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Printf("failed to read %s: %v", filename, err)
			return err
		}
		if strings.HasSuffix(file.Name(), ".json") {
			var site siteInfo
			err = json.Unmarshal(data, &site)
			if err != nil {
				return err
			}
			err = p.nginxsiteTmpl.Execute(&config, &site)
			if err != nil {
				return err
			}
		}
		if strings.HasSuffix(file.Name(), ".conf") {
			inBlock := false
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				startNewBlock := false
				block := "http"
				domain := ""
				if strings.HasPrefix(line, "# LETSENCRYPT-BEGIN") {
					var matches []string
					matches = blockRe.FindStringSubmatch(line)
					if matches != nil {
						block = matches[1]
					}
					matches = domainRe.FindStringSubmatch(line)
					if matches != nil {
						domain = matches[1]
					}
					startNewBlock = true
				} else if strings.HasPrefix(line, "# LETSENCRYPT-END") {
					inBlock = false
				}
				if !inBlock {
					config.WriteString(line)
					config.WriteByte('\n')
				}
				if startNewBlock {
					if block == "https" {
						config.WriteString(fmt.Sprintf("ssl_certificate %s;", p.getSslCertPath(domain)))
						config.WriteString(fmt.Sprintf("ssl_certificate_key %s;", p.getSslPrivateKeyPath(domain)))
						config.WriteRune('\n')
					}
					config.WriteString("location /.well-known/acme-challenge {")
					config.WriteString(fmt.Sprintf("  proxy_pass http://%s:%d;", p.letsEncryptServerHost, letsEncryptServerPort))
					config.WriteString("}")
					config.WriteRune('\n')
					if _, exists := p.sslCerts[domain]; !exists {
						p.sslCerts[domain] = nil
					}
					inBlock = true
				}

			}

		}
	}

	err = ioutil.WriteFile(nginxSitesConf, []byte(config.String()), 0644)
	if err != nil {
		return err
	}
	return nil
}

func (p *ProxyServer) startNginx() (*exec.Cmd, error) {
	cmd := exec.Command("nginx", "-c", nginxMainConfFile, "-g", "daemon off;")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("starting nginx: %v %v", cmd.Path, cmd.Args)
	err := cmd.Start()
	if err != nil {
		return nil, err
	}

	log.Printf("nginx running with PID %d", cmd.Process.Pid)
	return cmd, nil
}

func forwardSignals(signals <-chan os.Signal, process *os.Process) {
	for sig := range signals {
		log.Printf("forwarding signal %s to PID %d", sig, process.Pid)
		err := process.Signal(sig)
		if err != nil {
			log.Printf("failed to forward signal %s to PID %d: %v", sig, process.Pid, err)
		}
	}
}

func (p *ProxyServer) downloadSslCerts() (bool, error) {
	err := os.MkdirAll(nginxLetsEncryptConfigDir, 0755)
	if err != nil {
		log.Printf("failed to create %s: %v", nginxLetsEncryptConfigDir, err)
		return false, err
	}

	dumpURL := fmt.Sprintf("http://%s:%d/dump", p.letsEncryptServerHost, letsEncryptServerPort)
	req, err := http.NewRequest("GET", dumpURL, nil)
	if err != nil {
		return false, err
	}
	if p.letsEncryptDataLastModified != "" {
		req.Header.Set("If-Modified-Since", p.letsEncryptDataLastModified)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("request to %v failed: %v", dumpURL, err)
		return false, err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return false, nil
	}
	if p.letsEncryptDataLastModified == resp.Header.Get("Last-Modified") {
		// XXX temporary hack
		return false, nil
	}
	p.letsEncryptDataLastModified = resp.Header.Get("Last-Modified")

	log.Printf("downloading ssl certificates from %v to %v", dumpURL, nginxLetsEncryptConfigDir)
	log.Printf("ssl certificates were last modified at %v", p.letsEncryptDataLastModified)

	cmd := exec.Command("tar", "-x", "-C", nginxLetsEncryptConfigDir)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Print("failed to extract letsencrypt config: %v", err)
		return false, err
	}

	return true, nil
}

func (p *ProxyServer) updateSslCerts() (bool, error) {
	newCertURL := fmt.Sprintf("http://%s:%d/new-cert", p.letsEncryptServerHost, letsEncryptServerPort)

	for domain, sslCertInfo := range p.sslCerts {
		if sslCertInfo != nil {
			continue
		}
		form := url.Values{}
		form.Set("domain", domain)
		http.PostForm(newCertURL, form)
	}

	return p.downloadSslCerts()
}

func (p *ProxyServer) updateSslCertsForever(nginxProcess *os.Process) {
	defaultSleepDuration := 1 * time.Minute
	sleepDuration := defaultSleepDuration
	for {
		time.Sleep(sleepDuration)
		reload, err := p.updateSslCerts()
		if err != nil {
			sleepDuration = sleepDuration + sleepDuration/4
			continue
		}
		if reload {
			err = p.updateNginxConfFiles()
			if err != nil {
				log.Print("failed to update nginx config files")
				sleepDuration = sleepDuration + sleepDuration/4
				continue
			}
			log.Printf("sending SIGHUP to nginx with PID %d", nginxProcess.Pid)
			err = nginxProcess.Signal(syscall.SIGHUP)
			if err != nil {
				log.Print("failed to reload nginx")
				sleepDuration = sleepDuration + sleepDuration/4
				continue
			}
		}
		sleepDuration = defaultSleepDuration
	}
}

// Run the ProxyServer
func (p *ProxyServer) Run() error {
	p.letsEncryptServerHost = os.Getenv("LETSENCRYPT_SERVER_HOST")
	if p.letsEncryptServerHost == "" {
		return fmt.Errorf("LETSENCRYPT_SERVER_HOST missing or empty")
	}

	_, err := p.downloadSslCerts()
	if err != nil {
		log.Print("failed to download ssl certificates")
	}

	err = p.updateNginxConfFiles()
	if err != nil {
		log.Print("failed to update nginx config files")
		return err
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	nginxCmd, err := p.startNginx()

	go forwardSignals(signals, nginxCmd.Process)
	go p.updateSslCertsForever(nginxCmd.Process)

	err = nginxCmd.Wait()
	if err != nil {
		log.Printf("nginx finished with error: %v", err)
		return err
	}

	log.Print("nginx finished")
	return nil
}

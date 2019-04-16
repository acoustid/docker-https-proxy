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
	"strings"
	"syscall"
	"text/template"
	"time"
)

const defaultLetsEncryptServerHost = "localhost"
const defaultLetsEncryptServerPort = 12812

const nginxLetsEncryptConfigDir = "/etc/nginx/letsencrypt/"
const nginxMainConfFile = "/etc/nginx/nginx.conf"
const nginxSitesConf = "/etc/nginx/conf.d/50-sites.conf"

const snakeoilSslCert = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
const snakeoilSslPrivateKey = "/etc/ssl/private/ssl-cert-snakeoil.key"

type siteTemplateContext struct {
	Site        *siteInfo
	LetsEncrypt *letsEncryptInfo
}

type siteInfo struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	SSL      sslCertInfo
	Backends []siteBackendInfo `json:"backends"`
	Routes   []siteRouteInfo   `json:"routes"`
}

type letsEncryptInfo struct {
	Master       letsEncryptServerInfo
	lastModified string
}

type letsEncryptServerInfo struct {
	Host string
	Port int
}

type siteBackendInfo struct {
	Name        string
	Servers     []siteBackendServerInfo    `json:"servers"`
	HealthCheck siteBackendHealthCheckInfo `json:"healthcheck"`
}

type siteBackendServerInfo struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type siteBackendHealthCheckInfo struct {
	Path string `json:"path"`
}

type siteRouteInfo struct {
	Path    string `json:"path"`
	Backend string `json:"backend"`
}

const nginxConfTempate = `
resolver {{.Resolver}};

upstream letsencrypt_master {
	server {{.LetsEncrypt.Master.Host}}:{{.LetsEncrypt.Master.Port}};
}

{{range $site := .Sites}}
{{range .Backends}}
upstream {{$site.Name}}_backend_{{.Name}} {
{{range .Servers -}}
{{"\t"}}server {{.Host}}:{{.Port}};
{{- end}}
}
{{end}}
server {
	listen 80;
	listen [::]:80;

	server_name {{.Domain}};

	location /.well-known/acme-challenge {
		proxy_pass http://letsencrypt_master;
	}

	location / {
		return 302 https://$host$request_uri;
	}
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;

	server_name {{.Domain}};

	ssl_certificate {{.SSL.CertificatePath}};
	ssl_certificate_key {{.SSL.PrivateKeyPath}};

	client_max_body_size 0;

	location /.well-known/acme-challenge {
		proxy_pass http://letsencrypt_master;
	}
{{range .Routes}}
	location {{.Path}} {
		proxy_pass http://{{$site.Name}}_backend_{{.Backend}};
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
{{end -}}
}
{{end}}
`

type sslCertInfo struct {
	Valid           bool
	CertificatePath string
	PrivateKeyPath  string
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
	certPathExists, err := checkIfPathExists(i.CertificatePath)
	if err != nil {
		return false, err
	}
	privateKeyPathExists, err := checkIfPathExists(i.PrivateKeyPath)
	if err != nil {
		return false, err
	}
	return certPathExists && privateKeyPathExists, nil
}

// ProxyServer is a nginx-based load balancer / proxy.
type ProxyServer struct {
	exitCh       chan bool
	nginxProcess *os.Process
	nginxConfTpl *template.Template
	sslCerts     map[string]sslCertInfo
	Sites        []*siteInfo
	SitesDir     string
	LetsEncrypt  *letsEncryptInfo
	Resolver     string
}

// NewProxyServer creates a new ProxyServer instance.
func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		exitCh:       make(chan bool),
		nginxConfTpl: template.Must(template.New("config").Parse(nginxConfTempate)),
		Resolver:     defaultResolver,
		SitesDir:     defaultSitesDir,
		LetsEncrypt: &letsEncryptInfo{
			Master: letsEncryptServerInfo{
				Host: defaultLetsEncryptServerHost,
				Port: defaultLetsEncryptServerPort,
			},
		},
	}
}

func (p *ProxyServer) lookupSslCertInfo(domain string) sslCertInfo {
	info := p.sslCerts[domain]
	if !info.Valid {
		return sslCertInfo{
			CertificatePath: snakeoilSslCert,
			PrivateKeyPath:  snakeoilSslPrivateKey,
		}
	}
	return info
}

func (p *ProxyServer) loadSslCerts() error {
	sslCertDir := path.Join(nginxLetsEncryptConfigDir, "live")
	entries, err := ioutil.ReadDir(sslCertDir)
	if err != nil {
		if os.IsNotExist(err) {
			p.sslCerts = make(map[string]sslCertInfo)
			return nil
		}
		return err
	}

	p.sslCerts = make(map[string]sslCertInfo)
	for _, entry := range entries {
		if entry.IsDir() {
			domain := entry.Name()
			info := sslCertInfo{
				CertificatePath: path.Join(sslCertDir, domain, "fullchain.pem"),
				PrivateKeyPath:  path.Join(sslCertDir, domain, "privkey.pem"),
			}
			valid, err := info.Validate()
			if err != nil {
				return err
			}
			if valid {
				info.Valid = true
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

	files, err := ioutil.ReadDir(p.SitesDir)
	if err != nil {
		return err
	}

	p.Sites = nil
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		path := path.Join(p.SitesDir, file.Name())
		log.Printf("reading site config %v", path)
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Printf("failed to read site config %s: %v", path, err)
			return err
		}
		var site siteInfo
		err = json.Unmarshal(data, &site)
		if err != nil {
			return err
		}
		err = p.validateAndNormalizeSite(&site)
		if err != nil {
			return err
		}
		p.Sites = append(p.Sites, &site)
	}

	const tmpNginxSitesConf = nginxSitesConf + ".tmp"
	f, err := os.Create(tmpNginxSitesConf)
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(tmpNginxSitesConf)

	err = p.nginxConfTpl.Execute(f, p)
	if err != nil {
		return err
	}

	err = os.Rename(tmpNginxSitesConf, nginxSitesConf)
	if err != nil {
		return err
	}

	return nil
}

func (p *ProxyServer) validateAndNormalizeSite(site *siteInfo) error {
	site.SSL = p.lookupSslCertInfo(site.Domain)
	if len(site.Routes) == 0 {
		site.Routes = append(site.Routes, siteRouteInfo{Path: "/", Backend: site.Backends[0].Name})
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

	dumpURL := fmt.Sprintf("http://%s:%d/dump", p.LetsEncrypt.Master.Host, p.LetsEncrypt.Master.Port)
	req, err := http.NewRequest("GET", dumpURL, nil)
	if err != nil {
		return false, err
	}
	if p.LetsEncrypt.lastModified != "" {
		req.Header.Set("If-Modified-Since", p.LetsEncrypt.lastModified)
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
	if p.LetsEncrypt.lastModified == resp.Header.Get("Last-Modified") {
		// XXX temporary hack
		return false, nil
	}
	p.LetsEncrypt.lastModified = resp.Header.Get("Last-Modified")

	log.Printf("downloading ssl certificates from %v to %v", dumpURL, nginxLetsEncryptConfigDir)

	cmd := exec.Command("tar", "-x", "-C", nginxLetsEncryptConfigDir)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Printf("failed to extract letsencrypt config: %v", err)
		return false, err
	}

	return true, nil
}

func (p *ProxyServer) updateSslCerts() (bool, error) {
	newCertURL := fmt.Sprintf("http://%s:%d/new-cert", p.LetsEncrypt.Master.Host, p.LetsEncrypt.Master.Port)

	for _, site := range p.Sites {
		sslCertInfo := p.sslCerts[site.Domain]
		if sslCertInfo.Valid {
			continue
		}
		form := url.Values{}
		form.Set("domain", site.Domain)
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
	letsEncryptServerHost := os.Getenv("PROXY_LETSENCRYPT_SERVER_HOST")
	if letsEncryptServerHost == "" {
		return fmt.Errorf("PROXY_LETSENCRYPT_SERVER_HOST missing or empty")
	}
	p.LetsEncrypt.Master.Host = letsEncryptServerHost

	resolver := os.Getenv("PROXY_RESOLVER")
	if resolver != "" {
		p.Resolver = resolver
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

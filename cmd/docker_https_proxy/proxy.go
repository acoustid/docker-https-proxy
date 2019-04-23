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

const haproxyLetsEncryptDir = "/etc/haproxy/letsencrypt/"
const haproxySSLDir = "/etc/haproxy/ssl/"
const haproxyConfigFile = "/etc/haproxy/haproxy.cfg"

type siteInfo struct {
	Name               string `json:"name"`
	Domain             string `json:"domain"`
	DisableLetsEncrypt bool   `json:"disable_letsencrypt"`
	SSL                sslCertInfo
	Backends           []siteBackendInfo `json:"backends"`
	Routes             []siteRouteInfo   `json:"routes"`
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

const haproxyConfigTemplate = `
global
	maxconn 1024
	log stderr format raw daemon notice
	tune.ssl.default-dh-param 2048

defaults
	mode http
	timeout connect 60s
	timeout client 1h
	timeout server 1h
	log stdout format raw daemon
{{- if .EnableHTTPLog}}
	option httplog
{{- end}}

resolvers main
	nameserver dns1 {{$.Resolver}}:53


frontend fe_http
	bind *:80
	acl is_letsencrypt path_beg /.well-known/acme-challenge
	redirect scheme https code 301 if !is_letsencrypt
	use_backend be_letsencrypt if is_letsencrypt

frontend fe_https
	bind *:443 ssl crt {{$.SSLDir}} alpn h2,http/1.1
	acl is_letsencrypt path_beg /.well-known/acme-challenge
	use_backend be_letsencrypt if is_letsencrypt
{{range $site := .Sites -}}
{{"\t"}}acl domain_{{.Name}} ssl_fc_sni -i {{$site.Domain}}
{{range $i, $route := .Routes -}}
{{"\t"}}acl route_{{$site.Name}}_{{$i}} path_beg {{.Path}}
{{"\t"}}use_backend be_{{$site.Name}}_{{.Backend}} if domain_{{$site.Name}} route_{{$site.Name}}_{{$i}}
{{end}}
{{- end}}

backend be_letsencrypt
	balance roundrobin
	option httpchk GET /_health
	http-check expect status 200
	server-template srv_ 100 {{.LetsEncrypt.Master.Host}}:{{.LetsEncrypt.Master.Port}} check resolvers main

{{range $site := .Sites -}}
{{range $backend := .Backends}}
backend be_{{$site.Name}}_{{.Name}}
	balance roundrobin
{{- if .HealthCheck.Path}}
	option httpchk GET {{.HealthCheck.Path}}
	http-check expect status 200
{{- end}}
{{- range $i, $server := .Servers}}
{{"\t"}}server-template srv_{{$i}}_ 100 {{.Host}}:{{.Port}} check resolvers main
{{- end}}
{{end}}
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

// ProxyServer is a HAProxy-based load balancer.
type ProxyServer struct {
	exitCh            chan bool
	haproxy           *HAProxy
	haproxyConfigTmpl *template.Template
	sslCerts          map[string]sslCertInfo
	Sites             []*siteInfo
	SitesDir          string
	LetsEncrypt       *letsEncryptInfo
	Resolver          string
	SSLDir            string
	EnableHTTPLog     bool
	shutdown          bool
	shutdownDelay     time.Duration
}

// NewProxyServer creates a new ProxyServer instance.
func NewProxyServer() *ProxyServer {
	le := &letsEncryptInfo{
		Master: letsEncryptServerInfo{
			Host: defaultLetsEncryptServerHost,
			Port: defaultLetsEncryptServerPort,
		},
	}
	return &ProxyServer{
		exitCh:            make(chan bool),
		haproxy:           NewHAProxy(haproxyConfigFile),
		haproxyConfigTmpl: template.Must(template.New("config").Parse(haproxyConfigTemplate)),
		Resolver:          defaultResolver,
		SitesDir:          defaultSitesDir,
		LetsEncrypt:       le,
		SSLDir:            haproxySSLDir,
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
	sslCertDir := path.Join(haproxyLetsEncryptDir, "live")
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
				err = p.mergeCertificateFiles(domain, info.CertificatePath, info.PrivateKeyPath)
				if err != nil {
					return err
				}
				info.Valid = true
				p.sslCerts[domain] = info
			}
		}
	}
	return nil
}

func (p *ProxyServer) updateHAProxyConfigFile() error {
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

	const tmpHaproxyConfigFile = haproxyConfigFile + ".tmp"
	f, err := os.Create(tmpHaproxyConfigFile)
	if err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(tmpHaproxyConfigFile)

	err = p.haproxyConfigTmpl.Execute(f, p)
	if err != nil {
		return err
	}

	err = os.Rename(tmpHaproxyConfigFile, haproxyConfigFile)
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

func (p *ProxyServer) handleSignals(signals <-chan os.Signal) {
	var err error
	for sig := range signals {
		if sig == syscall.SIGINT {
			p.shutdown = true
			log.Printf("disabling healthcheck")
			time.Sleep(p.shutdownDelay)
			log.Printf("stopping haproxy")
			err = p.haproxy.Stop()
		} else if sig == syscall.SIGTERM {
			p.shutdown = true
			log.Printf("disabling healthcheck")
			time.Sleep(p.shutdownDelay)
			log.Printf("killing haproxy")
			err = p.haproxy.Kill()
		} else if sig == syscall.SIGHUP {
			err = p.haproxy.Reload()
		}
		if err != nil {
			log.Printf("failed to forward signal %s to haproxy: %v", sig, err)
		}
	}
}

func (p *ProxyServer) downloadSslCerts() (bool, error) {
	err := os.MkdirAll(haproxyLetsEncryptDir, 0755)
	if err != nil {
		log.Printf("failed to create %s: %v", haproxyLetsEncryptDir, err)
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

	log.Printf("downloading ssl certificates from %v to %v", dumpURL, haproxyLetsEncryptDir)

	cmd := exec.Command("tar", "-x", "-C", haproxyLetsEncryptDir)
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
		if site.DisableLetsEncrypt {
			continue
		}
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

func (p *ProxyServer) updateSslCertsForever() {
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
			err = p.updateHAProxyConfigFile()
			if err != nil {
				log.Printf("failed to update haproxy config file: %v", err)
				sleepDuration = sleepDuration + sleepDuration/4
				continue
			}
			err = p.haproxy.Reload()
			if err != nil {
				log.Printf("failed to reload haproxy: %v", err)
				sleepDuration = sleepDuration + sleepDuration/4
				continue
			}
		}
		sleepDuration = defaultSleepDuration
	}
}

func (p *ProxyServer) mergeCertificateFiles(name string, certificatePath string, privateKeyPath string) error {
	certificatData, err := ioutil.ReadFile(certificatePath)
	if err != nil {
		return err
	}
	privateKeyData, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}

	mergedPath := path.Join(p.SSLDir, name+".pem")
	f, err := os.Create(mergedPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(certificatData)
	if err != nil {
		os.Remove(mergedPath)
		return err
	}
	_, err = f.WriteString("\n")
	if err != nil {
		os.Remove(mergedPath)
		return err
	}
	_, err = f.Write(privateKeyData)
	if err != nil {
		os.Remove(mergedPath)
		return err
	}
	_, err = f.WriteString("\n")
	if err != nil {
		os.Remove(mergedPath)
		return err
	}
	return nil
}

func (p *ProxyServer) handleHealth(writer http.ResponseWriter, request *http.Request) {
	writer.WriteHeader(http.StatusOK)
	writer.Write([]byte("ok"))
}

func (p *ProxyServer) runUtilsServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/_health", p.handleHealth)
	server := &http.Server{Addr: fmt.Sprintf(":%d", defaultProxyUtilsServerPort), Handler: mux}
	return server.ListenAndServe()
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

	if IsTrueValue(os.Getenv("PROXY_HTTP_LOG")) {
		p.EnableHTTPLog = true
	}

	shutdownDelayStr := os.Getenv("PROXY_SHUTDOWN_DELAY")
	if shutdownDelayStr != "" {
		shutdownDelay, err := time.ParseDuration(shutdownDelayStr)
		if err != nil {
			return fmt.Errorf("failed to read PROXY_SHUTDOWN_DELAY: %v", err)
		}
		log.Printf("will delay shutdown by %v", shutdownDelay)
		p.shutdownDelay = shutdownDelay
	}

	var err error

	err = os.MkdirAll(p.SitesDir, 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(p.SSLDir, 0700)
	if err != nil {
		return err
	}

	err = p.mergeCertificateFiles("00-snakeoil", snakeoilSslCert, snakeoilSslPrivateKey)
	if err != nil {
		return err
	}

	_, err = p.downloadSslCerts()
	if err != nil {
		log.Print("failed to download ssl certificates")
	}

	err = p.updateHAProxyConfigFile()
	if err != nil {
		log.Printf("failed to create haproxy config file: %v", err)
		return err
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	err = p.haproxy.Start()
	if err != nil {
		log.Printf("failed to start haproxy: %v", err)
		return err
	}

	go p.handleSignals(signals)
	go p.updateSslCertsForever()
	go p.runUtilsServer()

	err = p.haproxy.Wait()
	if err != nil {
		log.Printf("haproxy finished with error: %v", err)
		return err
	}

	log.Print("haproxy finished")
	return nil
}

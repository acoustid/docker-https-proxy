package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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

const defaultLetsEncryptServerHost = "localhost"
const defaultLetsEncryptServerPort = 12812

const nginxLetsEncryptConfigDir = "/etc/nginx/letsencrypt/"
const nginxMainConfFile = "/etc/nginx/nginx.conf"
const nginxSitesDir = "/etc/nginx/sites/"
const nginxSitesConf = "/etc/nginx/conf.d/50-sites.conf"

const snakeoilSslCert = "/etc/ssl/certs/ssl-cert-snakeoil.pem"
const snakeoilSslPrivateKey = "/etc/ssl/private/ssl-cert-snakeoil.key"

const resolverHost = "127.0.0.11"

type siteTemplateContext struct {
	Site        *siteInfo
	LetsEncrypt *letsEncryptInfo
	Resolver    string
}

type siteInfo struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	SSL      sslCertInfo
	Backends []siteBackendInfo `json:"backend"`
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

const nginxSiteTempate = `
{{range .Site.Backends}}
upstream {{$.Site.Name}}_backend_{{.Name}} {
{{range .Servers -}}
{{"\t"}}server {{.Host}}:{{.Port}};
{{- end}}
}
{{end}}
server {
	listen 80;
	listen [::]:80;

	server_name {{.Site.Domain}};

	resolver {{.Resolver}};

	location /.well-known/acme-challenge {
		set ${{.Site.Name}}_letsencrypt_server {{.LetsEncrypt.Master.Host}};
		proxy_pass http://${{.Site.Name}}_letsencrypt_server:{{.LetsEncrypt.Master.Port}};
	}

	location / {
		return 302 https://$host$request_uri;
	}
}

server {
	listen 443 ssl;
	listen [::]:443 ssl;

	server_name {{.Site.Domain}};

	resolver {{.Resolver}};

	ssl_certificate {{.Site.SSL.CertificatePath}};
	ssl_certificate_key {{.Site.SSL.PrivateKeyPath}};

	client_max_body_size 0;

	location /.well-known/acme-challenge {
		set ${{.Site.Name}}_letsencrypt_server {{.LetsEncrypt.Master.Host}};
		proxy_pass http://${{.Site.Name}}_letsencrypt_server:{{.LetsEncrypt.Master.Port}};
	}
{{range .Site.Routes}}
	location {{.Path}} {
		proxy_pass http://{{$.Site.Name}}_backend_{{.Backend}};
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
`

type sslCertInfo struct {
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
	exitCh        chan bool
	nginxProcess  *os.Process
	nginxsiteTmpl *template.Template
	sslCerts      map[string]*sslCertInfo
	letsEncrypt   *letsEncryptInfo
}

// NewProxyServer creates a new ProxyServer instance.
func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		exitCh:        make(chan bool),
		nginxsiteTmpl: template.Must(template.New("config").Parse(nginxSiteTempate)),
		letsEncrypt: &letsEncryptInfo{
			Master: letsEncryptServerInfo{
				Host: defaultLetsEncryptServerHost,
				Port: defaultLetsEncryptServerPort,
			},
		},
	}
}

func (p *ProxyServer) getSslCertPath(domain string) string {
	info := p.sslCerts[domain]
	if info == nil {
		return snakeoilSslCert
	}
	return info.CertificatePath
}

func (p *ProxyServer) getSslPrivateKeyPath(domain string) string {
	info := p.sslCerts[domain]
	if info == nil {
		return snakeoilSslPrivateKey
	}
	return info.PrivateKeyPath
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
				CertificatePath: path.Join(sslCertDir, domain, "fullchain.pem"),
				PrivateKeyPath:  path.Join(sslCertDir, domain, "privkey.pem"),
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

func (p *ProxyServer) renderSiteTemplate(writer io.Writer, site *siteInfo) error {
	ctx := &siteTemplateContext{
		Site:        site,
		LetsEncrypt: p.letsEncrypt,
		Resolver:    resolverHost,
	}
	return p.nginxsiteTmpl.Execute(writer, ctx)
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
			site.SSL.CertificatePath = p.getSslCertPath(site.Domain)
			site.SSL.PrivateKeyPath = p.getSslPrivateKeyPath(site.Domain)
			if len(site.Routes) == 0 {
				site.Routes = append(site.Routes, siteRouteInfo{Path: "/", Backend: site.Backends[0].Name})
			}
			ctx := &siteTemplateContext{
				Site:        &site,
				LetsEncrypt: p.letsEncrypt,
				Resolver:    resolverHost,
			}
			err = p.nginxsiteTmpl.Execute(&config, ctx)
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
					config.WriteString(fmt.Sprintf("  proxy_pass http://%s:%d;", p.letsEncrypt.Master.Host, p.letsEncrypt.Master.Port))
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

	dumpURL := fmt.Sprintf("http://%s:%d/dump", p.letsEncrypt.Master.Host, p.letsEncrypt.Master.Port)
	req, err := http.NewRequest("GET", dumpURL, nil)
	if err != nil {
		return false, err
	}
	if p.letsEncrypt.lastModified != "" {
		req.Header.Set("If-Modified-Since", p.letsEncrypt.lastModified)
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
	if p.letsEncrypt.lastModified == resp.Header.Get("Last-Modified") {
		// XXX temporary hack
		return false, nil
	}
	p.letsEncrypt.lastModified = resp.Header.Get("Last-Modified")

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
	newCertURL := fmt.Sprintf("http://%s:%d/new-cert", p.letsEncrypt.Master.Host, p.letsEncrypt.Master.Port)

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
	letsEncryptServerHost := os.Getenv("LETSENCRYPT_SERVER_HOST")
	if letsEncryptServerHost == "" {
		return fmt.Errorf("LETSENCRYPT_SERVER_HOST missing or empty")
	}
	p.letsEncrypt.Master.Host = letsEncryptServerHost

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

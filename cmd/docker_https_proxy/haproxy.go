package main

import (
	"log"
	"os"
	"os/exec"
	"syscall"
)

// HAProxy represents a running HAProxy process
type HAProxy struct {
	cmd *exec.Cmd
}

// NewHAProxy creates a new HAProxy instance
func NewHAProxy(configPath string) *HAProxy {
	cmd := exec.Command("haproxy", "-f", configPath, "-W")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return &HAProxy{cmd: cmd}
}

// Start starts the HAProxy server
func (h *HAProxy) Start() error {
	log.Printf("starting HAProxy: %v %v", h.cmd.Path, h.cmd.Args)
	err := h.cmd.Start()
	if err != nil {
		log.Printf("haproxy failed to start: %v", err)
		return err
	}
	log.Printf("haproxy running with PID %d", h.cmd.Process.Pid)
	return nil
}

// Stop gracefully shuts down the HAProxy server
func (h *HAProxy) Stop() error {
	return h.Signal(syscall.SIGUSR1)
}

// Kill shuts down the HAProxy server immediately
func (h *HAProxy) Kill() error {
	return h.Signal(syscall.SIGTERM)
}

// Reload signals the HAProxy process to reload the config file
func (h *HAProxy) Reload() error {
	return h.Signal(syscall.SIGUSR2)
}

// Signal sends the given signal to the HAProxy process
func (h *HAProxy) Signal(sig os.Signal) error {
	process := h.cmd.Process
	log.Printf("sending signal %v to PID %d", sig, process.Pid)
	return process.Signal(sig)
}

// Wait blocks until the HAProxy process to stops
func (h *HAProxy) Wait() error {
	return h.cmd.Wait()
}

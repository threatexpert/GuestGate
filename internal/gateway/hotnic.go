package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func restConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "vmrest.cfg")
}

func restMarker(path string, data []byte) string {
	return filepath.Join(filepath.Dir(path), fmt.Sprintf(".guestgate-rest-%x", sha256.Sum256(data)))
}

func ownsRESTConfig(path string, data []byte) bool {
	a, err := os.Stat(path)
	if err != nil {
		return false
	}
	b, err := os.Stat(restMarker(path, data))
	return err == nil && os.SameFile(a, b)
}

func needsRESTPassword() bool {
	path := restConfigPath()
	data, err := os.ReadFile(path)
	return err == nil && !ownsRESTConfig(path, data)
}

// Workstation reads this per-user file even when its socket is private.
// Publish a complete file exclusively and remove only the file we created.
func restCredentials(path, supplied string) (string, string, func(), error) {
	b, err := os.ReadFile(path)
	if err == nil && ownsRESTConfig(path, b) {
		// Recover the two hard links after a previous worker was forcibly stopped.
		if err = os.Remove(path); err != nil {
			return "", "", nil, err
		}
		if err = os.Remove(restMarker(path, b)); err != nil {
			return "", "", nil, err
		}
		b, err = os.ReadFile(path)
	}
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && key == "username" && value != "" && supplied != "" {
				return value, supplied, func() {}, nil
			}
		}
		return "", "", nil, fmt.Errorf("请输入本机已有的 VMware REST 账户密码")
	}
	if !os.IsNotExist(err) {
		return "", "", nil, err
	}
	var random [36]byte
	if _, err = rand.Read(random[:]); err != nil {
		return "", "", nil, err
	}
	user := "GuestGate-" + hex.EncodeToString(random[:6])
	salt := hex.EncodeToString(random[6:14])
	pass := hex.EncodeToString(random[14:])
	hash, err := bcrypt.GenerateFromPassword([]byte(salt+pass), bcrypt.DefaultCost)
	if err != nil {
		return "", "", nil, err
	}
	data := []byte(fmt.Sprintf("port=8697\r\nusername=%s\r\npassword=%s\r\nsalt=%s\r\n", user, hash, salt))
	marker := restMarker(path, data)
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", "", nil, err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		os.Remove(marker)
		return "", "", nil, errors.Join(err, closeErr)
	}
	if err = os.Link(marker, path); err != nil {
		os.Remove(marker)
		return "", "", nil, fmt.Errorf("无法独占创建 VMware 临时凭据: %w", err)
	}
	clean := func() {
		if current, e := os.ReadFile(path); e == nil && bytes.Equal(current, data) && ownsRESTConfig(path, data) {
			if e = os.Remove(path); e != nil {
				return
			}
		}
		os.Remove(marker)
	}
	return user, pass, clean, nil
}

type vmREST struct {
	client     *http.Client
	user, pass string
}

const vmMedia = "application/vnd.vmware.vmw.rest-v1+json"

func (r vmREST) call(ctx context.Context, method, path string, body, out any) error {
	var data bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&data).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost/api/"+path, &data)
	if err != nil {
		return err
	}
	req.SetBasicAuth(r.user, r.pass)
	req.Header.Set("Accept", vmMedia)
	req.Header.Set("Content-Type", vmMedia)
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("VMware REST %s %s: %s", method, path, resp.Status)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
	}
	return nil
}

type restVM struct{ ID, Path string }
type restNIC struct {
	Index                   int
	Type, VMnet, MACAddress string
}

func (r vmREST) switchNIC(ctx context.Context, v VM) error {
	var vms []restVM
	if err := r.call(ctx, "GET", "vms", nil, &vms); err != nil {
		return err
	}
	var target restVM
	for _, item := range vms {
		if strings.EqualFold(filepath.Clean(item.Path), filepath.Clean(v.Path)) {
			target = item
			break
		}
	}
	if target.ID == "" {
		if err := r.call(ctx, "POST", "vms/registration", map[string]string{"name": v.Name, "path": v.Path}, &target); err != nil {
			return err
		}
		if target.ID == "" || !strings.EqualFold(filepath.Clean(target.Path), filepath.Clean(v.Path)) {
			return fmt.Errorf("VMware 未确认所选虚拟机的注册路径")
		}
	}
	nicPath := "vms/" + url.PathEscape(target.ID) + "/nic"
	read := func() (restNIC, error) {
		var list struct{ NICs []restNIC }
		if err := r.call(ctx, "GET", nicPath, nil, &list); err != nil {
			return restNIC{}, err
		}
		if len(list.NICs) != 1 {
			return restNIC{}, adapterCountError(len(list.NICs))
		}
		if !strings.EqualFold(list.NICs[0].MACAddress, v.MAC) {
			return restNIC{}, fmt.Errorf("虚拟机网卡已变化，请刷新列表")
		}
		return list.NICs[0], nil
	}
	nic, err := read()
	if err != nil {
		return err
	}
	kind, network := "hostonly", "vmnet1"
	params := map[string]string{"type": kind}
	if v.isolated {
		kind = "custom"
		network = v.Network
		params = map[string]string{"type": kind, "vmnet": strings.Replace(network, "vmnet", "VMnet", 1)}
	}
	if err = r.call(ctx, "PUT", nicPath+"/"+strconv.Itoa(nic.Index), params, nil); err != nil {
		return err
	}
	nic, err = read()
	if err != nil {
		return err
	}
	if !strings.EqualFold(nic.Type, kind) || !strings.EqualFold(nic.VMnet, network) {
		return fmt.Errorf("VMware 未确认网卡已连接 %s", network)
	}
	return nil
}

func switchHostOnly(parent context.Context, v VM, password string) error {
	vmrest := filepath.Join(filepath.Dir(v.vmrun), "vmrest.exe")
	if info, err := os.Stat(vmrest); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("热切换需要 VMware Workstation 的 vmrest.exe，请检查 %s", vmrest)
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp(os.Getenv("LOCALAPPDATA"), "gg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "VMware", "vmrest.sock")
	if len([]byte(sock)) >= 108 {
		return fmt.Errorf("VMware 管理套接字路径过长")
	}
	if err = os.Mkdir(filepath.Dir(sock), 0700); err != nil {
		return err
	}
	user, pass, clean, err := restCredentials(restConfigPath(), password)
	if err != nil {
		return err
	}
	defer clean()
	cmd := exec.CommandContext(ctx, vmrest, "-U", "-p", "-1")
	cmd.Env = append(os.Environ(), "LOCALAPPDATA="+dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err = cmd.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	defer func() { cancel(); <-exited }()
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}
	transport := &http.Transport{DialContext: dial}
	defer transport.CloseIdleConnections()
	r := vmREST{&http.Client{Transport: transport, Timeout: 15 * time.Second}, user, pass}
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			return fmt.Errorf("VMware 本地管理服务未能启动")
		case <-ticker.C:
			// Dial readiness avoids depending on vmrest's localized console output.
			c, err := dial(ctx, "", "")
			if err != nil {
				continue
			}
			c.Close()
			if err = r.switchNIC(ctx, v); err != nil {
				return err
			}
			for {
				disk, err := readVM(v.Path, map[string]netip.Prefix{v.Network: v.subnet})
				if err == nil && disk.Reason == "" && !disk.NeedsSwitch && disk.Network == v.Network && disk.device == v.device && strings.EqualFold(disk.MAC, v.MAC) {
					return nil
				}
				select {
				case <-ctx.Done():
					return fmt.Errorf("等待 VMware 写回 %s: %w", v.Network, ctx.Err())
				case <-ticker.C:
				}
			}
		}
	}
}

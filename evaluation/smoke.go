// Command smoke runs selected release executables in a disposable Linux container.
// Every identity, workload and credential is generated solely for this exercise.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type runner struct {
	ctx  context.Context
	env  []string
	http *http.Client
	step string
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	r := &runner{ctx: ctx, env: []string{"PATH=/inputs/bin:/bin:/usr/bin", "HOME=/work/home", "USER=nobody", "JOBMAN_NO_EXTENSIONS=1"}}
	if err := r.run(); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"passed": false, "step": r.step, "reason": err.Error()})
		fmt.Fprintln(os.Stderr, "synthetic evaluation failed:", r.step, err)
		os.Exit(1)
	}
}

func private(name string, data []byte) error {
	return os.WriteFile(filepath.Join("/work", name), data, 0o600)
}

func (r *runner) command(input string, expected int, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(r.ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/inputs/bin/"+name, args...)
	cmd.Dir, cmd.Env, cmd.Stdin = "/work", r.env, strings.NewReader(input)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	err := cmd.Run()
	status := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return nil, errors.New("executable did not finish")
		}
		status = exit.ExitCode()
	}
	if status != expected || output.Len() > 4<<20 {
		return nil, fmt.Errorf("%s returned status %d", name, status)
	}
	return output.Bytes(), nil
}

func (r *runner) start(name string, extra []string, args ...string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(r.ctx, "/inputs/bin/"+name, args...)
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = "/work", append(append([]string{}, r.env...), extra...), io.Discard, io.Discard
	return cmd, cmd.Start()
}

func stop(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func (r *runner) request(method, origin, path, key string, body any, expected int) (map[string]any, error) {
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(r.ctx, method, origin+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer synthetic-evaluation-token")
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	response, err := r.http.Do(req)
	if err != nil {
		return nil, errors.New("HTTP dependency unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 || response.StatusCode != expected {
		return nil, fmt.Errorf("HTTP status %d, expected %d", response.StatusCode, expected)
	}
	var value map[string]any
	if err = json.Unmarshal(data, &value); err != nil {
		return nil, errors.New("invalid JSON response")
	}
	return value, nil
}

func (r *runner) ready(origin string) error {
	for range 100 {
		if _, err := r.request("GET", origin, "/healthz", "", nil, 200); err == nil {
			return nil
		}
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return errors.New("service did not become ready")
}

func certificateAuthority(name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
}

func material() (*x509.CertPool, error) {
	serverCA, serverKey, serverPEM, err := certificateAuthority("Synthetic evaluation server CA")
	if err != nil {
		return nil, err
	}
	_, agentKey, agentPEM, err := certificateAuthority("Synthetic evaluation agent CA")
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, serverCA, &leafKey.PublicKey, serverKey)
	if err != nil {
		return nil, err
	}
	leafDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	agentDER, err := x509.MarshalPKCS8PrivateKey(agentKey)
	if err != nil {
		return nil, err
	}
	for name, data := range map[string][]byte{"server-ca.crt": serverPEM, "server.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "server.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafDER}), "agent-ca.crt": agentPEM, "agent-ca.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: agentDER})} {
		if err = private(name, data); err != nil {
			return nil, err
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(serverPEM) {
		return nil, errors.New("invalid generated CA")
	}
	return roots, nil
}

func (r *runner) run() error {
	r.step = "isolated runtime"
	if runtime.GOOS != "linux" || os.Getuid() == 0 {
		return errors.New("evaluation requires non-root Linux")
	}
	if err := os.Chdir("/work"); err != nil {
		return err
	}
	for _, name := range []string{"home", "artifacts", "local"} {
		if err := os.Mkdir(name, 0o700); err != nil {
			return err
		}
	}
	r.step = "synthetic TLS and Control startup"
	roots, err := material()
	if err != nil {
		return err
	}
	r.http = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	control, err := r.start("jobman-control", []string{"JOBMAN_CONTROL_DATABASE_URL=postgres://postgres:evaluation-only@postgres:5432/evaluation?sslmode=disable", "JOBMAN_CONTROL_DEVELOPMENT_AUTH=true", "JOBMAN_CONTROL_DEVELOPMENT_NAMESPACE=evaluation", "JOBMAN_CONTROL_LISTEN=127.0.0.1:18443", "JOBMAN_CONTROL_TLS_CERT_FILE=/work/server.crt", "JOBMAN_CONTROL_TLS_KEY_FILE=/work/server.key", "JOBMAN_CONTROL_AGENT_CA_CERT_FILE=/work/agent-ca.crt", "JOBMAN_CONTROL_AGENT_CA_KEY_FILE=/work/agent-ca.key"})
	if err != nil {
		return err
	}
	defer stop(control)
	origin := "https://127.0.0.1:18443"
	if err = r.ready(origin); err != nil {
		return err
	}
	r.step = "authorized target and mTLS agent enrollment"
	target, err := r.request("POST", origin, "/v1/namespaces/evaluation/targets", "evaluation-target", map[string]any{"apiVersion": "jobman.control/v1alpha1", "kind": "Target", "metadata": map[string]any{"name": "evaluation-host"}, "spec": map[string]any{"kind": "host", "executionBackend": "subprocess", "runtimes": []string{"native"}, "operatingSystems": []string{"linux"}, "architectures": []string{runtime.GOARCH}, "logStore": map[string]any{"name": "evaluation", "version": 1}}}, 201)
	if err != nil {
		return err
	}
	metadata, ok := target["metadata"].(map[string]any)
	if !ok {
		return errors.New("target metadata absent")
	}
	generation, ok := metadata["generationId"].(string)
	if !ok || generation == "" {
		return errors.New("target generation absent")
	}
	enrollment, err := r.request("POST", origin, "/v1/namespaces/evaluation/targets/evaluation-host/enrollment-tokens", "evaluation-enrollment", map[string]any{"apiVersion": "jobman.control/v1alpha1", "kind": "AgentEnrollmentToken", "spec": map[string]any{"principal": map[string]any{"issuer": "jobman-control-development", "subject": "local-developer"}, "expectedUser": "nobody"}}, 201)
	if err != nil {
		return err
	}
	spec, ok := enrollment["spec"].(map[string]any)
	if !ok {
		return errors.New("enrollment shape invalid")
	}
	token, ok := spec["token"].(string)
	if !ok {
		return errors.New("enrollment token absent")
	}
	if _, err = r.command(token+"\n", 0, "jobman-agent", "enroll", "--state-dir", "/work/agent", "--server", origin, "--server-ca", "/work/server-ca.crt", "--target-generation", generation); err != nil {
		return err
	}
	startAgent := func() (*exec.Cmd, error) {
		return r.start("jobman-agent", nil, "run", "--state-dir", "/work/agent", "--poll-interval", "250ms", "--artifact-store", "evaluation", "--artifact-root", "/work/artifacts")
	}
	agent, err := startAgent()
	if err != nil {
		return err
	}
	defer func() { stop(agent) }()
	if err = private("token", []byte("synthetic-evaluation-token")); err != nil {
		return err
	}
	configuration := map[string]any{"schema_version": 1, "shared": map[string]any{"current_profile": "evaluation", "profiles": map[string]any{"evaluation": map[string]any{"endpoint": origin, "namespace": "evaluation", "token_file": "/work/token", "ca_file": "/work/server-ca.crt", "artifact_roots": map[string]any{"evaluation": map[string]any{"version": 1, "path": "/work/artifacts"}}}}}}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		return err
	}
	if err = private("client.yaml", encoded); err != nil {
		return err
	}
	shared := func(expected int, args ...string) ([]byte, error) {
		return r.command("", expected, "jobman", append([]string{"--config", "/work/client.yaml", "--state-dir", "/work/client", "shared"}, args...)...)
	}
	r.step = "shared job submission"
	job, err := shared(0, "run", "--json", "--name", "evaluation-restart", "--target", "evaluation-host", "--", "/bin/sh", "-c", "printf 'evaluation-start\\n'; sleep 15; printf 'evaluation-complete\\n'")
	if err != nil {
		return err
	}
	var submitted struct {
		Job struct {
			Metadata struct {
				ID string `json:"id"`
			} `json:"metadata"`
		} `json:"job"`
	}
	if err = json.Unmarshal(job, &submitted); err != nil {
		return errors.New("shared submission JSON invalid")
	}
	jobID := submitted.Job.Metadata.ID
	if len(jobID) != 36 {
		return errors.New("job identity invalid")
	}
	r.step = "shared job dispatch"
	statusPath := "/v1/namespaces/evaluation/jobs/" + jobID
	started := false
	for range 100 {
		value, requestErr := r.request("GET", origin, statusPath, "", nil, 200)
		if requestErr == nil {
			if status, valid := value["status"].(map[string]any); valid && status["phase"] == "running" {
				started = true
				break
			}
		}
		select {
		case <-r.ctx.Done():
			return r.ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !started {
		return errors.New("shared job did not start")
	}
	before, err := r.command("", 0, "jobman-agent", "status", "--state-dir", "/work/agent", "--json")
	if err != nil {
		return err
	}
	stop(agent)
	agent, err = startAgent()
	if err != nil {
		return err
	}
	if _, err = shared(0, "wait", "--timeout", "45s", jobID); err != nil {
		return err
	}
	after, err := r.command("", 0, "jobman-agent", "status", "--state-dir", "/work/agent", "--json")
	if err != nil {
		return err
	}
	if !bytes.Equal(before, after) {
		return errors.New("agent enrollment identity changed")
	}
	logs, err := shared(0, "logs", jobID)
	if err != nil {
		return err
	}
	if !bytes.Contains(logs, []byte("evaluation-start")) || !bytes.Contains(logs, []byte("evaluation-complete")) {
		return errors.New("shared logs incomplete")
	}
	r.step = "namespace denial"
	if _, err = r.request("GET", origin, "/v1/namespaces/denied/jobs", "", nil, 403); err != nil {
		return err
	}
	r.step = "deterministic failure diagnosis"
	failed, err := r.command("", 0, "jobman", "--state-dir", "/work/local", "run", "--name", "evaluation-failure", "--", "/bin/false")
	if err != nil {
		return err
	}
	failedID := strings.TrimSpace(string(failed))
	if _, err = r.command("", 1, "jobman", "--state-dir", "/work/local", "wait", failedID); err != nil {
		return err
	}
	report, err := r.command("", 0, "jobman-diagnose", "--jobman", "/inputs/bin/jobman", "--state-dir", "/work/local", "--json", failedID)
	if err != nil {
		return err
	}
	var diagnosis map[string]any
	if err = json.Unmarshal(report, &diagnosis); err != nil {
		return errors.New("diagnosis JSON invalid")
	}
	subject, ok := diagnosis["subject"].(map[string]any)
	if !ok || subject["outcome"] != "failure" {
		return errors.New("diagnosis outcome differs")
	}
	r.step = "Dashboard fixture monitoring and denial"
	dashboard, err := r.start("jobman-dashboard", nil, "--fixture", "--listen", "127.0.0.1:18088", "--web", "/inputs/web")
	if err != nil {
		return err
	}
	defer stop(dashboard)
	fixture := "http://127.0.0.1:18088"
	if err = r.ready(fixture); err != nil {
		return err
	}
	if _, err = r.request("GET", fixture, "/api/v1/bootstrap", "", nil, 200); err != nil {
		return err
	}
	if _, err = r.request("GET", fixture, "/api/v1/jobs", "", nil, 200); err != nil {
		return err
	}
	if _, err = r.request("GET", fixture, "/api/v1/deployments/11111111-1111-4111-8111-111111111111/namespaces/99999999-9999-4999-8999-999999999999/jobs/00000000-0000-4000-8000-000000000000", "", nil, 403); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"schemaVersion": 1, "passed": true, "sharedExecution": true, "agentRestartPreservedExecutionAndIdentity": true, "sharedLogsVerified": true, "namespaceDenial": true, "deterministicDiagnosis": true, "dashboardFixtureMonitoringAndDenial": true, "dashboardLiveControlIntegration": false, "expiredCertificateRecoveryInduced": false, "corporateIdentityAcceptance": false, "appleDeliveryAcceptance": false})
}

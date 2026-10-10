package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test executable itself is the mock iperf process. No remote endpoint is used.
func init() {
	if os.Getenv("VPS_TEST_IPERF_HELPER") != "1" {
		return
	}
	if len(os.Args) != 13 || os.Args[1] != "-c" || os.Args[3] != "-p" || os.Args[5] != "-R" || os.Args[6] != "-O" || os.Args[7] != "3" || os.Args[8] != "-t" || os.Args[10] != "-P" || os.Args[12] != "-J" {
		fmt.Fprint(os.Stderr, "unexpected arguments")
		os.Exit(7)
	}
	switch os.Args[2] {
	case "sleep.test":
		if p := os.Getenv("VPS_TEST_STARTED"); p != "" {
			_ = os.WriteFile(p, []byte("started"), 0600)
		}
		time.Sleep(30 * time.Second)
	case "bad.test":
		fmt.Print("not JSON")
		os.Exit(0)
	case "missing.test":
		fmt.Print(`{"end":{}}`)
		os.Exit(0)
	case "negative.test":
		fmt.Print(`{"end":{"sum_received":{"bits_per_second":-1}}}`)
		os.Exit(0)
	case "zero.test":
		fmt.Print(`{"end":{"sum_received":{"bits_per_second":0}}}`)
		os.Exit(0)
	case "error.test":
		fmt.Print(`{"error":"connection refused"}`)
		os.Exit(1)
	case "jsonerror.test":
		fmt.Print(`{"error":"server busy"}`)
		os.Exit(0)
	case "exit.test":
		fmt.Fprint(os.Stderr, "missing dependency")
		os.Exit(3)
	case "false-success.test":
		fmt.Print(`{"end":{"sum_received":{"bits_per_second":99999999}}}`)
		os.Exit(2)
	}
	fmt.Fprint(os.Stderr, "diagnostic on stderr must not break JSON")
	fmt.Print(`{"end":{"sum_received":{"bits_per_second":123450000}}}`)
	os.Exit(0)
}

func testApp(t *testing.T) *application {
	t.Helper()
	a, err := newApplication(t.TempDir(), listenAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.cancel)
	a.iperfPath = ""
	return a
}

func helperPath(t *testing.T) string {
	t.Helper()
	t.Setenv("VPS_TEST_IPERF_HELPER", "1")
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func request(a *application, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://"+a.authority+path, nil)
	if token != "" {
		req.Header.Set("X-App-Token", token)
	}
	recorder := httptest.NewRecorder()
	a.handler().ServeHTTP(recorder, req)
	return recorder
}

func TestParameterValidation(t *testing.T) {
	for _, bad := range []string{"host=", "host=bad%0Ahost", "host=-bad", "host=https://example.com", "host=a&port=0", "host=a&port=65536", "host=a&t=-1", "host=a&t=301", "host=a&t=999999999999999999999999", "host=a&P=33", "host=a&P=1.5", "host=a&t=1&t=2"} {
		values, _ := url.ParseQuery(bad)
		if _, err := parseParams(values); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	values, _ := url.ParseQuery("host=EXAMPLE.COM.&port=05201&t=300&P=32")
	p, err := parseParams(values)
	if err != nil || p != (testParams{"example.com", 5201, 300, 32}) {
		t.Fatalf("normalization: %+v %v", p, err)
	}
	p, err = parseParams(url.Values{"host": {"[::1]"}})
	if err != nil || p != (testParams{"::1", 5201, 10, 1}) {
		t.Fatalf("defaults: %+v %v", p, err)
	}
}

func TestNodesValidation(t *testing.T) {
	a := testApp(t)
	nodes, err := a.readNodes()
	if err != nil || nodes == nil || len(nodes) != 0 {
		t.Fatal(nodes, err)
	}
	path := filepath.Join(a.dir, "nodes.json")
	for _, bad := range []string{`[{"name":"a","host":"a"},]`, `null`, `{}`, `[{"name":"","host":"a"}]`, `[{"name":"a","host":"a","port":65536}]`, `[{"name":"a","host":"A."},{"name":"b","host":"a","port":5201}]`} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := a.readNodes(); err == nil {
			t.Errorf("accepted %s", bad)
		}
		if r := request(a, "GET", "/nodes", ""); r.Code != 500 {
			t.Fatal(r.Code)
		}
	}
	valid := "\uFEFF" + `[{"name":"<b>name</b>","host":"EXAMPLE.COM","port":"5201"}]`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	nodes, err = a.readNodes()
	if err != nil || len(nodes) != 1 || nodes[0].Host != "example.com" {
		t.Fatal(nodes, err)
	}
}

func TestCSVQuotingBOMAndAppend(t *testing.T) {
	a := testApp(t)
	row := []string{"2026-09-22 12:00:00", "comma,quote\"and\nnewline", "5201", "10", "1", "0.0", "成功"}
	if err := a.appendCSV(row); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(a.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "\uFEFF") {
		t.Fatal("missing BOM")
	}
	read := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\uFEFF")))
	records, err := read.ReadAll()
	if err != nil || !reflect.DeepEqual(records, [][]string{csvHeader, row}) {
		t.Fatalf("roundtrip: %q %v", records, err)
	}
	// Append to a file without its last newline; preserve its complete prefix.
	prefix := strings.TrimSuffix(string(data), "\r\n")
	if err := os.WriteFile(a.logPath, []byte(prefix), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.appendCSV(row); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(a.logPath)
	if !strings.HasPrefix(string(data), prefix) {
		t.Fatal("old data changed")
	}
	read = csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\uFEFF")))
	records, err = read.ReadAll()
	if err != nil || len(records) != 3 {
		t.Fatal(records, err)
	}
}

func TestDataRecoveryAndWarnings(t *testing.T) {
	a := testApp(t)
	if err := a.appendCSV([]string{"2026-09-22 12:00:00", "example.com", "5201", "10", "1", "0.0", "成功"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(a.logPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("broken,row\r\n2026-09-22 12:00:01,example.com,5201,10,1,NaN,成功\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.appendCSV([]string{"2026-09-22 12:00:02", "example.com", "5201", "10", "1", "12.3", "成功"}); err != nil {
		t.Fatal(err)
	}
	rows, warnings, err := a.readData()
	if err != nil || len(rows) != 2 || rows[0].Mbps != 0 || len(warnings) != 1 {
		t.Fatal(rows, warnings, err)
	}
	response := request(a, "GET", "/data", "")
	if response.Code != 200 || response.Header().Get("X-Data-Warning") == "" || !strings.HasPrefix(response.Body.String(), "[") {
		t.Fatal(response)
	}
	if err := os.WriteFile(a.logPath, []byte("wrong,header\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if r := request(a, "GET", "/data", ""); r.Code != 500 {
		t.Fatal(r)
	}
}

func TestConcurrentCSVSnapshot(t *testing.T) {
	a := testApp(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 15; j++ {
				if err := a.appendCSV([]string{"2026-09-22 12:00:00", "example.com", "5201", "10", "1", "1.0", "成功"}); err != nil {
					t.Error(err)
					return
				}
				if _, warnings, err := a.readData(); err != nil || len(warnings) != 0 {
					t.Errorf("snapshot: %v %v", warnings, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	rows, _, err := a.readData()
	if err != nil || len(rows) != 120 {
		t.Fatal(len(rows), err)
	}
}

func TestProcessResults(t *testing.T) {
	path := helperPath(t)
	cases := []struct {
		host     string
		ok       bool
		mbps     float64
		contains string
	}{
		{"success.test", true, 123.5, ""}, {"zero.test", true, 0, ""}, {"bad.test", false, 0, "JSON"},
		{"missing.test", false, 0, "缺少"}, {"negative.test", false, 0, "缺少"}, {"error.test", false, 0, "connection refused"},
		{"jsonerror.test", false, 0, "server busy"}, {"exit.test", false, 0, "missing dependency"}, {"false-success.test", false, 0, "异常退出"},
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result := executeTest(ctx, path, testParams{c.host, 5201, 10, 1})
			if result.Ok != c.ok || result.Mbps != c.mbps || !strings.Contains(result.Err, c.contains) {
				t.Fatalf("%+v", result)
			}
		})
	}
	if r := executeTest(context.Background(), filepath.Join(t.TempDir(), "missing.exe"), testParams{}); !strings.Contains(r.Err, "无法启动") {
		t.Fatal(r)
	}
	if r := executeTest(context.Background(), "", testParams{}); !strings.Contains(r.Err, "未找到") {
		t.Fatal(r)
	}
}

func TestProcessTimeout(t *testing.T) {
	path := helperPath(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	result := executeTest(ctx, path, testParams{"sleep.test", 5201, 1, 1})
	if !strings.Contains(result.Err, "超时") || time.Since(start) > 3*time.Second {
		t.Fatal(result)
	}
}

func TestRequestBoundaryAndNoAutoExit(t *testing.T) {
	a := testApp(t)
	for _, path := range []string{"/test?host=a", "/quit"} {
		if r := request(a, "GET", path, ""); r.Code != 405 {
			t.Fatal(r)
		}
		if r := request(a, "POST", path, ""); r.Code != 403 {
			t.Fatal(r)
		}
	}
	for _, header := range []struct{ key, value string }{{"Host", "attacker.test"}, {"Origin", "https://attacker.test"}, {"Sec-Fetch-Site", "cross-site"}} {
		req := httptest.NewRequest("POST", "http://"+a.authority+"/test?host=a", nil)
		req.Header.Set("X-App-Token", a.token)
		if header.key == "Host" {
			req.Host = header.value
		} else {
			req.Header.Set(header.key, header.value)
		}
		rec := httptest.NewRecorder()
		a.handler().ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatal(header, rec)
		}
	}
	for _, path := range []string{"/bye", "/ping", "/unknown"} {
		if r := request(a, "GET", path, ""); r.Code != 404 {
			t.Fatal(r)
		}
	}
	if strings.Contains(indexHTML, "pagehide") || strings.Contains(indexHTML, "setInterval") {
		t.Fatal("auto-exit remains")
	}
	if r := request(a, "POST", "/test?host=a&t=301", a.token); r.Code != 400 {
		t.Fatal(r)
	}
	if _, err := os.Stat(a.logPath); !os.IsNotExist(err) {
		t.Fatal("rejected request wrote CSV")
	}
}

func TestResultAndSaveFailureAreIndependent(t *testing.T) {
	a := testApp(t)
	a.iperfPath = helperPath(t)
	if err := os.Mkdir(a.logPath, 0700); err != nil {
		t.Fatal(err)
	}
	rec := request(a, "POST", "/test?host=success.test", a.token)
	var result testResp
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || !result.Ok || result.Saved || result.SaveError == "" {
		t.Fatal(rec.Code, result)
	}
}

func TestMissingDependencyIsLogged(t *testing.T) {
	a := testApp(t)
	rec := request(a, "POST", "/test?host=example.com", a.token)
	var result testResp
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Ok || !result.Saved || !strings.Contains(result.Err, "未找到") {
		t.Fatal(result)
	}
	data, err := os.ReadFile(a.logPath)
	if err != nil || !strings.Contains(string(data), "失败") {
		t.Fatal(string(data), err)
	}
}

func TestBusyAndGracefulCancellation(t *testing.T) {
	a := testApp(t)
	a.iperfPath = helperPath(t)
	started := filepath.Join(t.TempDir(), "started")
	t.Setenv("VPS_TEST_STARTED", started)
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() { finished <- request(a, "POST", "/test?host=sleep.test", a.token) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rec := request(a, "POST", "/test?host=example.com", a.token); rec.Code != 409 {
		t.Fatal(rec)
	}
	if rec := request(a, "POST", "/quit", a.token); rec.Code != 200 {
		t.Fatal(rec)
	}
	select {
	case rec := <-finished:
		var result testResp
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Ok || !result.Saved || !strings.Contains(result.Err, "取消") {
			t.Fatal(result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test process did not stop")
	}
	if rec := request(a, "POST", "/test?host=example.com", a.token); rec.Code != 503 {
		t.Fatal(rec)
	}
	data, err := os.ReadFile(a.logPath)
	if err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\uFEFF"))).ReadAll()
	if err != nil || len(records) != 2 || records[1][6] != "失败" {
		t.Fatal(records, err)
	}
}

func TestIdentityProbe(t *testing.T) {
	a := testApp(t)
	server := httptest.NewServer(a.handler())
	defer server.Close()
	a.authority = strings.TrimPrefix(server.URL, "http://")
	if !isExistingService(server.URL) {
		t.Fatal("own app not recognized")
	}
	stranger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `{"app":"different"}`) }))
	defer stranger.Close()
	if isExistingService(stranger.URL) {
		t.Fatal("foreign app recognized")
	}
}

func historyRequest(a *application, path string, payload interface{}, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "http://"+a.authority+path, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Token", token)
	rec := httptest.NewRecorder()
	a.handler().ServeHTTP(rec, req)
	return rec
}

func historyFixture(t *testing.T, a *application) ([]byte, []dataRow) {
	t.Helper()
	header := "\uFEFF" + strings.Join(csvHeader, ",") + "\r\n"
	success := "\"2026-09-22 12:00:00\",example.com,5201,10,1,12.3,成功\r\n"
	failure := "2026-09-22 12:00:01,example.com,5201,10,1,-,失败\n"
	raw := []byte(header + success + failure + success)
	if err := os.WriteFile(a.logPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	rows, _, err := a.readData()
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	return raw, rows
}

func TestDeleteExactDuplicateAndUndo(t *testing.T) {
	a := testApp(t)
	before, rows := historyFixture(t, a)
	if rows[0].ID == rows[1].ID {
		t.Fatal("duplicate records need distinct IDs")
	}
	payload := map[string]interface{}{"ids": []string{rows[1].ID}}
	if r := historyRequest(a, "/history/delete", payload, ""); r.Code != 403 {
		t.Fatal(r)
	}
	if r := request(a, "GET", "/history/delete", a.token); r.Code != 405 {
		t.Fatal(r)
	}
	r := historyRequest(a, "/history/delete", payload, a.token)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body.String())
	}
	var result struct {
		Deleted int    `json:"deleted"`
		Undo    string `json:"undo"`
		Backup  string `json:"backup"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 {
		t.Fatal(result)
	}
	after, err := os.ReadFile(a.logPath)
	if err != nil {
		t.Fatal(err)
	}
	last := []byte("\"2026-09-22 12:00:00\",example.com,5201,10,1,12.3,成功\r\n")
	if string(after) != string(before[:len(before)-len(last)]) {
		t.Fatal("unselected bytes changed")
	}
	backup, err := os.ReadFile(filepath.Join(a.dir, result.Backup))
	if err != nil || string(backup) != string(before) {
		t.Fatal("backup mismatch", err)
	}
	if r := historyRequest(a, "/history/undo", map[string]string{"id": result.Undo}, ""); r.Code != 403 {
		t.Fatal(r)
	}
	if r := historyRequest(a, "/history/undo", map[string]string{"id": result.Undo}, a.token); r.Code != 200 {
		t.Fatal(r)
	}
	restored, _ := os.ReadFile(a.logPath)
	if string(restored) != string(before) {
		t.Fatal("undo must be byte exact")
	}
	if r := historyRequest(a, "/history/undo", map[string]string{"id": result.Undo}, a.token); r.Code != 409 {
		t.Fatal(r)
	}
}

func TestDeleteBatchAndStaleSelection(t *testing.T) {
	a := testApp(t)
	before, rows := historyFixture(t, a)
	for _, ids := range [][]string{{}, {rows[0].ID, rows[0].ID}, {rows[0].ID, fileRevision(before) + ":999"}} {
		r := historyRequest(a, "/history/delete", map[string]interface{}{"ids": ids}, a.token)
		if r.Code != 400 {
			t.Fatal(r.Code, r.Body.String())
		}
		raw, _ := os.ReadFile(a.logPath)
		if string(raw) != string(before) {
			t.Fatal("invalid request changed log")
		}
	}
	if err := a.appendCSV([]string{"2026-09-22 12:00:02", "new.test", "5201", "10", "1", "1.0", "成功"}); err != nil {
		t.Fatal(err)
	}
	if r := historyRequest(a, "/history/delete", map[string]interface{}{"ids": []string{rows[0].ID}}, a.token); r.Code != 409 {
		t.Fatal(r)
	}
	rows, _, _ = a.readData()
	ids := []string{}
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	if r := historyRequest(a, "/history/delete", map[string]interface{}{"ids": ids}, a.token); r.Code != 200 {
		t.Fatal(r)
	}
	remaining, _, err := a.readData()
	if err != nil || len(remaining) != 0 {
		t.Fatal(remaining, err)
	}
	raw, _ := os.ReadFile(a.logPath)
	if !strings.Contains(string(raw), "失败") || !strings.HasPrefix(string(raw), "\uFEFF"+strings.Join(csvHeader, ",")) {
		t.Fatal("header or failed record removed")
	}
}

func TestDeleteBackupFailureAndMalformedCSV(t *testing.T) {
	a := testApp(t)
	before, rows := historyFixture(t, a)
	if err := os.WriteFile(filepath.Join(a.dir, "backups"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	if r := historyRequest(a, "/history/delete", map[string]interface{}{"ids": []string{rows[0].ID}}, a.token); r.Code != 500 {
		t.Fatal(r)
	}
	raw, _ := os.ReadFile(a.logPath)
	if string(raw) != string(before) {
		t.Fatal("backup failure changed data")
	}
	broken := append(append([]byte{}, before...), []byte("broken,row\r\n")...)
	if err := os.WriteFile(a.logPath, broken, 0600); err != nil {
		t.Fatal(err)
	}
	rows, _, _ = a.readData()
	if r := historyRequest(a, "/history/delete", map[string]interface{}{"ids": []string{rows[0].ID}}, a.token); r.Code != 409 {
		t.Fatal(r)
	}
	raw, _ = os.ReadFile(a.logPath)
	if string(raw) != string(broken) {
		t.Fatal("malformed data changed")
	}
}

func TestUndoDoesNotOverwriteNewMeasurement(t *testing.T) {
	a := testApp(t)
	_, rows := historyFixture(t, a)
	r := historyRequest(a, "/history/delete", map[string]interface{}{"ids": []string{rows[0].ID}}, a.token)
	if r.Code != 200 {
		t.Fatal(r)
	}
	id := a.undo.ID
	if err := a.appendCSV([]string{"2026-09-22 12:00:02", "new.test", "5201", "10", "1", "1.0", "成功"}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(a.logPath)
	if r := historyRequest(a, "/history/undo", map[string]string{"id": id}, a.token); r.Code != 409 {
		t.Fatal(r)
	}
	after, _ := os.ReadFile(a.logPath)
	if string(after) != string(before) {
		t.Fatal("new measurement overwritten")
	}
}

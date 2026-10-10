package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const appID = "vps-speedtest-local"
const appVersion = "2.2.0"
const listenAddress = "127.0.0.1:8123"

var csvHeader = []string{"测试时间", "目标", "端口", "时长(s)", "线程", "下行Mbps", "状态"}

type application struct {
	dir, logPath, iperfPath, token, authority string
	csvMu, testMu, lifeMu                     sync.Mutex
	closing                                   bool
	ctx                                       context.Context
	cancel                                    context.CancelFunc
	quit                                      chan struct{}
	quitOnce                                  sync.Once
	undo                                      *historyUndo // protected by csvMu
}

func newApplication(dir, authority string) (*application, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &application{dir: dir, logPath: filepath.Join(dir, "speedtest_log.csv"),
		iperfPath: findIperf(dir), token: hex.EncodeToString(secret), authority: authority,
		ctx: ctx, cancel: cancel, quit: make(chan struct{})}, nil
}

func findIperf(dir string) string {
	for _, p := range []string{filepath.Join(dir, "iperf3.exe"), filepath.Join(dir, "iperf3", "iperf3.exe")} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("iperf3.exe"); err == nil {
		return p
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	b, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "响应编码失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]interface{}{"ok": false, "err": message})
}

// Only the exact loopback authority is served. Mutations also require a random
// per-process token, obtained by this same-origin UI through /session.
func (a *application) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.Host != a.authority || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+a.authority) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeError(w, http.StatusForbidden, "仅允许本机页面访问")
			return
		}
		method := http.MethodGet
		switch r.URL.Path {
		case "/test", "/quit", "/history/delete", "/history/undo":
			method = http.MethodPost
		case "/", "/chart", "/nodes", "/data", "/session", "/health":
		default:
			http.NotFound(w, r)
			return
		}
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeError(w, http.StatusMethodNotAllowed, "请求方法不支持")
			return
		}
		if method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-App-Token")), []byte(a.token)) != 1 {
			writeError(w, http.StatusForbidden, "会话已失效，请刷新页面")
			return
		}
		switch r.URL.Path {
		case "/health":
			writeJSON(w, 200, map[string]string{"app": appID, "version": appVersion})
		case "/session":
			writeJSON(w, 200, map[string]string{"token": a.token})
		case "/nodes":
			a.handleNodes(w, r)
		case "/data":
			a.handleData(w, r)
		case "/test":
			a.handleTest(w, r)
		case "/quit":
			a.handleQuit(w, r)
		case "/history/delete":
			a.handleDelete(w, r)
		case "/history/undo":
			a.handleUndo(w, r)
		case "/", "/chart":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			page := indexHTML
			if r.URL.Path == "/chart" {
				page = chartHTML
			}
			_, _ = io.WriteString(w, page)
		}
	})
}

type testParams struct {
	Host                   string
	Port, Seconds, Streams int
}

func normalizeHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	name := strings.TrimSuffix(host, ".")
	if len(name) == 0 || len(name) > 253 {
		return "", errors.New("请输入有效的 IP 或域名")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("域名格式无效")
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return "", errors.New("目标只接受 IP 或 ASCII 域名，不包含协议、路径或端口")
			}
		}
	}
	return strings.ToLower(name), nil
}

func boundedInt(raw, name string, fallback, upper int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > upper {
		return 0, fmt.Errorf("%s必须为 1–%d 的整数", name, upper)
	}
	return n, nil
}

func parseParams(q url.Values) (testParams, error) {
	var p testParams
	var err error
	for _, key := range []string{"host", "port", "t", "P"} {
		if len(q[key]) > 1 {
			return p, fmt.Errorf("参数 %s 重复", key)
		}
	}
	if p.Host, err = normalizeHost(q.Get("host")); err != nil {
		return p, err
	}
	if p.Port, err = boundedInt(q.Get("port"), "端口", 5201, 65535); err != nil {
		return p, err
	}
	if p.Seconds, err = boundedInt(q.Get("t"), "时长", 10, 300); err != nil {
		return p, err
	}
	p.Streams, err = boundedInt(q.Get("P"), "并发流", 1, 32)
	return p, err
}

type testResp struct {
	Ok        bool    `json:"ok"`
	Mbps      float64 `json:"mbps"`
	Err       string  `json:"err,omitempty"`
	Saved     bool    `json:"saved"`
	SaveError string  `json:"saveError,omitempty"`
	T         string  `json:"t"`
}

func executeTest(ctx context.Context, path string, p testParams) testResp {
	if path == "" {
		return testResp{Err: "未找到 iperf3.exe，请放入程序同目录或 iperf3 子目录，或加入 PATH 后重启"}
	}
	cmd := exec.CommandContext(ctx, path, "-c", p.Host, "-p", strconv.Itoa(p.Port), "-R", "-O", "3", "-t", strconv.Itoa(p.Seconds), "-P", strconv.Itoa(p.Streams), "-J")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, runErr := cmd.Output()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return testResp{Err: "测速超时，进程已终止"}
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return testResp{Err: "服务正在退出，测速已取消"}
	}
	var result struct {
		End struct {
			SumReceived struct {
				BPS *float64 `json:"bits_per_second"`
			} `json:"sum_received"`
		} `json:"end"`
		Error string `json:"error"`
	}
	parseErr := json.Unmarshal(out, &result)
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return testResp{Err: "无法启动 iperf3: " + runErr.Error()}
		}
		detail := strings.TrimSpace(stderr.String())
		if parseErr == nil && result.Error != "" {
			detail = result.Error
		}
		if len(detail) > 1000 {
			detail = detail[:1000]
		}
		if detail == "" {
			detail = "请检查服务端、iperf3 版本及运行依赖（DLL）"
		}
		return testResp{Err: fmt.Sprintf("iperf3 异常退出 (%d): %s", exitErr.ExitCode(), detail)}
	}
	if parseErr != nil {
		return testResp{Err: "iperf3 返回的 JSON 无效: " + parseErr.Error()}
	}
	if result.Error != "" {
		return testResp{Err: result.Error}
	}
	bps := result.End.SumReceived.BPS
	if bps == nil || *bps < 0 || math.IsNaN(*bps) || math.IsInf(*bps, 0) {
		return testResp{Err: "iperf3 输出缺少有效的接收吞吐结果"}
	}
	// A completed measurement with an explicit zero is valid, not a connection error.
	return testResp{Ok: true, Mbps: math.Round(*bps/1e6*10) / 10}
}

func (a *application) handleTest(w http.ResponseWriter, r *http.Request) {
	p, err := parseParams(r.URL.Query())
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	a.lifeMu.Lock()
	if a.closing {
		a.lifeMu.Unlock()
		writeError(w, 503, "服务正在退出")
		return
	}
	acquired := a.testMu.TryLock()
	a.lifeMu.Unlock()
	if !acquired {
		writeError(w, 409, "已有测试进行中")
		return
	}
	defer a.testMu.Unlock()
	// Accepted tests survive a tab close, but stop on explicit service shutdown.
	ctx, cancel := context.WithTimeout(a.ctx, time.Duration(p.Seconds+20)*time.Second)
	defer cancel()
	result := executeTest(ctx, a.iperfPath, p)
	result.T = time.Now().Format("2006-01-02 15:04:05")
	speed, status := "-", "失败"
	if result.Ok {
		speed, status = strconv.FormatFloat(result.Mbps, 'f', 1, 64), "成功"
	}
	err = a.appendCSV([]string{result.T, p.Host, strconv.Itoa(p.Port), strconv.Itoa(p.Seconds), strconv.Itoa(p.Streams), speed, status})
	result.Saved = err == nil
	if err != nil {
		result.SaveError = "记录未能确认保存: " + err.Error()
	}
	writeJSON(w, 200, result)
}

// Keep the existing seven columns and BOM; never rewrite historical records.
func (a *application) appendCSV(cols []string) (err error) {
	a.csvMu.Lock()
	defer a.csvMu.Unlock()
	f, err := os.OpenFile(a.logPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	stat, err := f.Stat()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	writer.UseCRLF = true
	if stat.Size() == 0 {
		buf.WriteString("\uFEFF")
		if err := writer.Write(csvHeader); err != nil {
			return err
		}
	} else {
		// A pre-existing file may have no final newline. Do not merge two rows.
		tail := []byte{0}
		if _, err := f.ReadAt(tail, stat.Size()-1); err != nil {
			return err
		}
		if tail[0] != '\n' {
			buf.WriteString("\r\n")
		}
	}
	if err := writer.Write(cols); err != nil {
		return err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	n, err := f.Write(buf.Bytes())
	if err != nil {
		return err
	}
	if n != buf.Len() {
		return io.ErrShortWrite
	}
	return f.Sync()
}

type node struct {
	Name string      `json:"name"`
	Host string      `json:"host"`
	Port json.Number `json:"port"`
}

func (a *application) readNodes() ([]node, error) {
	raw, err := os.ReadFile(filepath.Join(a.dir, "nodes.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []node{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("无法读取 nodes.json: %w", err)
	}
	var nodes []node
	if err := json.Unmarshal(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF}), &nodes); err != nil {
		return nil, fmt.Errorf("nodes.json 格式错误: %w", err)
	}
	if nodes == nil {
		return nil, errors.New("nodes.json 必须是数组，不能是 null")
	}
	seen := make(map[string]bool)
	for i := range nodes {
		n := &nodes[i]
		n.Name = strings.TrimSpace(n.Name)
		if n.Name == "" {
			return nil, fmt.Errorf("节点 %d 缺少名称", i+1)
		}
		host, err := normalizeHost(n.Host)
		if err != nil {
			return nil, fmt.Errorf("节点 %d: %w", i+1, err)
		}
		port, err := boundedInt(n.Port.String(), "节点端口", 5201, 65535)
		if err != nil {
			return nil, fmt.Errorf("节点 %d: %w", i+1, err)
		}
		n.Host, n.Port = host, json.Number(strconv.Itoa(port))
		key := net.JoinHostPort(host, n.Port.String())
		if seen[key] {
			return nil, fmt.Errorf("节点 %d 地址和端口重复: %s", i+1, key)
		}
		seen[key] = true
	}
	return nodes, nil
}

func (a *application) handleNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.readNodes()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, nodes)
}

type dataRow struct {
	ID     string  `json:"id"`
	T      string  `json:"t"`
	Target string  `json:"target"`
	IP     string  `json:"ip"`
	Thr    string  `json:"thr"`
	Mbps   float64 `json:"mbps"`
}

func (a *application) readData() ([]dataRow, []string, error) {
	rows, warnings := []dataRow{}, []string{}
	a.csvMu.Lock()
	raw, err := os.ReadFile(a.logPath)
	a.csvMu.Unlock()
	if errors.Is(err, os.ErrNotExist) {
		return rows, warnings, nil
	}
	if err != nil {
		return rows, warnings, fmt.Errorf("无法读取历史记录: %w", err)
	}
	names := map[string]string{}
	nodes, nodeErr := a.readNodes()
	if nodeErr != nil {
		warnings = append(warnings, nodeErr.Error())
	}
	for _, n := range nodes {
		names[n.Host+":"+n.Port.String()] = n.Name
	}
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(raw), "\uFEFF")))
	reader.FieldsPerRecord = 7
	header, err := reader.Read()
	if err == io.EOF {
		return rows, warnings, nil
	}
	if err != nil || strings.Join(header, "\x00") != strings.Join(csvHeader, "\x00") {
		return rows, warnings, errors.New("历史 CSV 表头不符合七列格式，未修改原文件")
	}
	damaged := 0
	revision := fmt.Sprintf("%x", sha256.Sum256(raw))
	index := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		index++
		if err != nil {
			damaged++
			continue
		}
		status := strings.TrimSpace(record[6])
		if status == "失败" {
			continue
		}
		if status != "成功" {
			damaged++
			continue
		}
		speed, err := strconv.ParseFloat(strings.TrimSpace(record[5]), 64)
		if err != nil || speed < 0 || math.IsNaN(speed) || math.IsInf(speed, 0) {
			damaged++
			continue
		}
		if _, err := time.ParseInLocation("2006-01-02 15:04:05", record[0], time.Local); err != nil {
			damaged++
			continue
		}
		host, err := normalizeHost(record[1])
		if err != nil {
			damaged++
			continue
		}
		port, err := boundedInt(record[2], "端口", 5201, 65535)
		if err != nil {
			damaged++
			continue
		}
		// Historical stream counts are preserved even if outside today's input limits.
		streams, err := strconv.Atoi(record[4])
		if err != nil || streams < 1 {
			damaged++
			continue
		}
		key := host + ":" + strconv.Itoa(port)
		name := names[key]
		if name == "" {
			name = key
		}
		rows = append(rows, dataRow{ID: fmt.Sprintf("%s:%d", revision, index), T: record[0], Target: name, IP: key, Thr: record[4], Mbps: speed})
	}
	if damaged > 0 {
		warnings = append(warnings, fmt.Sprintf("发现 %d 处损坏记录，已跳过可识别的坏记录；未闭合引号可能影响后续记录，原文件未修改", damaged))
	}
	return rows, warnings, nil
}

func (a *application) handleData(w http.ResponseWriter, r *http.Request) {
	rows, warnings, err := a.readData()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	// Keep /data's array contract; encode warnings into an ASCII response header.
	if len(warnings) > 0 {
		w.Header().Set("X-Data-Warning", url.QueryEscape(strings.Join(warnings, "；")))
	}
	writeJSON(w, 200, rows)
}

type historyUndo struct {
	ID, Backup, Before, After string
}

func fileRevision(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func decodeHistoryRequest(w http.ResponseWriter, r *http.Request, value interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeError(w, 400, "删除请求格式无效")
		return false
	}
	if decoder.Decode(new(interface{})) != io.EOF {
		writeError(w, 400, "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}

// Stage a complete file, then replace the old file. A failed write/rename leaves
// the original in place. The deletion backup is completed before this is called.
func replaceHistory(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".history-*.tmp")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(temp, path)
}

func (a *application) handleDelete(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		IDs []string `json:"ids"`
	}
	if !decodeHistoryRequest(w, r, &payload) {
		return
	}
	if len(payload.IDs) == 0 || len(payload.IDs) > 100 {
		writeError(w, 400, "每次请选择 1–100 条记录")
		return
	}
	a.csvMu.Lock()
	defer a.csvMu.Unlock()
	raw, err := os.ReadFile(a.logPath)
	if err != nil {
		writeError(w, 500, "无法读取记录: "+err.Error())
		return
	}
	revision := fileRevision(raw)
	selected := make(map[string]bool, len(payload.IDs))
	for _, id := range payload.IDs {
		if !strings.HasPrefix(id, revision+":") {
			writeError(w, 409, "记录已变化，请刷新记录后重新选择；本次未删除")
			return
		}
		if selected[id] {
			writeError(w, 400, "记录不能重复选择")
			return
		}
		selected[id] = true
	}
	prefix := 0
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		prefix = 3
	}
	reader := csv.NewReader(bytes.NewReader(raw[prefix:]))
	reader.FieldsPerRecord = 7
	header, err := reader.Read()
	if err != nil || strings.Join(header, "\x00") != strings.Join(csvHeader, "\x00") {
		writeError(w, 409, "CSV 表头异常，未删除任何记录")
		return
	}
	var retained bytes.Buffer
	retained.Write(raw[:int64(prefix)+reader.InputOffset()])
	count, index := 0, 0
	for {
		start := int64(prefix) + reader.InputOffset()
		record, err := reader.Read()
		end := int64(prefix) + reader.InputOffset()
		if err == io.EOF {
			retained.Write(raw[start:])
			break
		}
		if err != nil {
			writeError(w, 409, "CSV 存在损坏记录，请先检查备份；本次未删除")
			return
		}
		index++
		id := fmt.Sprintf("%s:%d", revision, index)
		if selected[id] && strings.TrimSpace(record[6]) == "成功" {
			count++
		} else {
			retained.Write(raw[start:end])
		}
	}
	if count != len(selected) {
		writeError(w, 400, "包含不存在或不可删除的记录，本次未删除")
		return
	}
	backupDir := filepath.Join(a.dir, "backups", "deletions")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		writeError(w, 500, "备份失败，未删除: "+err.Error())
		return
	}
	backup, err := os.CreateTemp(backupDir, "speedtest-"+time.Now().Format("20060102-150405")+"-*.csv")
	if err != nil {
		writeError(w, 500, "备份失败，未删除: "+err.Error())
		return
	}
	if _, err = backup.Write(raw); err == nil {
		err = backup.Sync()
	}
	closeErr := backup.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(backup.Name())
		writeError(w, 500, "备份写入失败，未删除任何记录")
		return
	}
	if err := replaceHistory(a.logPath, retained.Bytes()); err != nil {
		writeError(w, 500, "替换记录失败，原始备份已保留: "+err.Error())
		return
	}
	backupName := filepath.Base(backup.Name())
	a.undo = &historyUndo{ID: backupName, Backup: backup.Name(), Before: revision, After: fileRevision(retained.Bytes())}
	writeJSON(w, 200, map[string]interface{}{"ok": true, "deleted": count, "undo": backupName, "backup": filepath.Join("backups", "deletions", backupName)})
}

func (a *application) handleUndo(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ID string `json:"id"`
	}
	if !decodeHistoryRequest(w, r, &payload) {
		return
	}
	a.csvMu.Lock()
	defer a.csvMu.Unlock()
	if a.undo == nil || payload.ID != a.undo.ID {
		writeError(w, 409, "撤销已失效；原始备份仍保存在 backups/deletions")
		return
	}
	raw, err := os.ReadFile(a.logPath)
	if err != nil || fileRevision(raw) != a.undo.After {
		writeError(w, 409, "删除后已有新记录或其他变更，不能直接撤销以免覆盖；原始备份仍保留")
		return
	}
	before, err := os.ReadFile(a.undo.Backup)
	if err != nil || fileRevision(before) != a.undo.Before {
		writeError(w, 500, "备份读取或校验失败，未修改当前记录")
		return
	}
	if err := replaceHistory(a.logPath, before); err != nil {
		writeError(w, 500, "撤销失败: "+err.Error())
		return
	}
	a.undo = nil
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (a *application) handleQuit(w http.ResponseWriter, r *http.Request) {
	a.lifeMu.Lock()
	a.closing = true
	a.cancel()
	a.lifeMu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
	a.quitOnce.Do(func() { close(a.quit) })
}

func openBrowser(address string) error {
	cmd := exec.Command("explorer.exe", address)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func isExistingService(address string) bool {
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Get(address + "/health")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	var identity struct {
		App     string `json:"app"`
		Version string `json:"version"`
	}
	return response.StatusCode == 200 && json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&identity) == nil && identity.App == appID && identity.Version == appVersion
}

func reportStartupError(dir, message string) {
	_ = os.WriteFile(filepath.Join(dir, "startup-error.log"), []byte(time.Now().Format(time.RFC3339)+" "+message+"\r\n"), 0644)
	text, _ := syscall.UTF16PtrFromString(message)
	title, _ := syscall.UTF16PtrFromString("VPS 下行测速")
	proc := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	if proc.Find() == nil {
		_, _, _ = proc.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
	}
}

func main() {
	path, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	address := "http://" + listenAddress
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		if isExistingService(address) {
			if err := openBrowser(address + "/"); err != nil {
				reportStartupError(dir, "无法打开浏览器: "+err.Error())
			}
		} else {
			reportStartupError(dir, "无法监听 "+listenAddress+"，请检查端口占用；旧版程序请先退出。\n"+err.Error())
		}
		return
	}
	app, err := newApplication(dir, listenAddress)
	if err != nil {
		_ = listener.Close()
		reportStartupError(dir, "无法创建会话: "+err.Error())
		return
	}
	defer app.cancel()
	server := &http.Server{Handler: app.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	// Used only by isolated automated checks; normal double-click opens the UI.
	if os.Getenv("VPS_SPEEDTEST_NO_BROWSER") != "1" {
		if err := openBrowser(address + "/"); err != nil {
			reportStartupError(dir, "浏览器启动失败，请手动打开 "+address+"\n"+err.Error())
		}
	}
	select {
	case <-app.quit:
	case err := <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			reportStartupError(dir, "HTTP 服务异常: "+err.Error())
		}
	}
	app.cancel()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
	}
	// Do not abandon an accepted test's process wait or CSV write on shutdown.
	app.testMu.Lock()
	app.testMu.Unlock()
	app.csvMu.Lock()
	app.csvMu.Unlock()
}

const indexHTML = `<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPS 下行测速</title>
<style>
:root{--fg:#192d3b;--mut:#657b89;--line:#e3ebef;--a2:#087eae;--a1:#05977a;--bad:#c44358;--bg:#f3f7f9;--panel:#fff}
*{box-sizing:border-box;margin:0}body{min-height:100vh;background:radial-gradient(ellipse at 8% 0%,#e4f4ee,transparent 45%),var(--bg);color:var(--fg);font:14px/1.6 system-ui,"Microsoft YaHei",sans-serif}
main{max-width:1200px;margin:0 auto;padding:32px 24px 48px}header{margin-bottom:24px}.eyebrow{font:600 11px/1.5 system-ui;letter-spacing:.18em;color:var(--a1);margin-bottom:5px}h1{font-size:28px;letter-spacing:-.03em}h2{font-size:17px;font-weight:700}.subtitle{color:var(--mut);margin-top:5px}.hint{font-size:12px;color:var(--mut)}
button{font:inherit;font-weight:500;cursor:pointer;border:1px solid var(--line);border-radius:9px;padding:9px 14px;background:#fff;color:var(--fg);display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:42px}button:hover{border-color:var(--a2);color:var(--a2)}button:disabled{opacity:.45;cursor:not-allowed}:focus-visible{outline:3px solid #79bdd8;outline-offset:3px}
.toolbar{position:sticky;top:12px;z-index:10;display:flex;align-items:center;gap:8px;background:#fffffff5;border:1px solid var(--line);border-radius:12px;padding:10px 14px;box-shadow:0 5px 24px #244b600a;margin-bottom:20px}.toolbar-label{margin-right:auto;color:var(--mut);font-size:12px;display:flex;align-items:center;gap:8px}.dot{width:7px;height:7px;background:var(--a1);border-radius:50%}#quit,.danger{color:var(--bad)}#quit:hover,.danger:hover{border-color:var(--bad);color:var(--bad)}
.panel{background:#fff;border:1px solid var(--line);border-radius:16px;box-shadow:0 5px 24px #244b6006;padding:22px;min-width:0}.section-heading{margin-bottom:20px}.test-layout{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(0,1fr);gap:28px}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}#host{grid-column:1/-1}label{display:block;font-size:12px;color:var(--mut);margin-bottom:6px}input,select{width:100%;min-width:0;background:#f8fafb;border:1px solid var(--line);border-radius:8px;color:var(--fg);padding:10px;font:14px system-ui;min-height:42px}input:focus,select:focus{outline:none;border-color:var(--a1);box-shadow:0 0 0 3px #05977a18}#selwrap{margin-bottom:14px}#go{grid-column:1/-1;background:var(--fg);color:white;border-color:var(--fg);margin-top:4px}#go:hover{background:#274858}
.result{background:linear-gradient(145deg,#f0f8f5,#f3f8fc);border:1px solid var(--line);border-radius:12px;padding:24px;display:flex;flex-direction:column;justify-content:center;min-width:0}.result-label{color:var(--a1);font-size:12px}.result-foot{font-size:12px;color:var(--mut);margin-top:16px}#num{font:600 clamp(32px,4vw,56px)/1.3 ui-monospace,Consolas,monospace;color:var(--a1);margin:16px 0;overflow-wrap:anywhere;min-height:80px}#num small{font:14px/1.8 system-ui;color:var(--mut)}#num.err{color:var(--bad);font:14px/1.8 system-ui;white-space:pre-wrap}#num.wait{animation:p 1.2s infinite}@keyframes p{50%{opacity:.35}}#bar{height:4px;background:#dce9e7;border-radius:99px;overflow:hidden;margin-top:8px}#fill{height:100%;width:0;background:linear-gradient(90deg,var(--a1),var(--a2))}.service-note{color:var(--mut);font-size:12px;margin:12px 0 20px;line-height:1.8}
.history-actions{position:sticky;top:86px;z-index:9;background:#fff;border-bottom:1px solid var(--line);padding:12px 0;display:flex;align-items:center;gap:8px;flex-wrap:wrap}.history-actions button{font-size:12px;padding:7px 10px;min-height:36px}.history-actions label{display:flex;align-items:center;gap:6px;margin:0 6px 0 0;font-size:12px}input[type=checkbox]{width:17px;height:17px;min-height:0;padding:0;accent-color:var(--a1);cursor:pointer}#page-info{font-size:12px;color:var(--mut)}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:13px 12px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}th{color:var(--mut);font-size:12px;font-weight:500;background:#f8fafb}td{font-variant-numeric:tabular-nums}tbody tr:hover{background:#f5faf8}.ok{color:var(--a1);font-weight:600}.row-delete{font-size:12px;padding:4px 9px;min-height:30px}#delete-note:empty{display:none}.table-wrap{overflow-x:auto;margin-top:12px}
dialog{width:min(480px,calc(100% - 32px));max-height:85vh;margin:auto;padding:24px;border:1px solid var(--line);border-radius:16px;color:var(--fg);box-shadow:0 16px 60px #0003}dialog::backdrop{background:#192d3b66}dialog h2{margin-bottom:12px}#delete-items{max-height:32vh;overflow:auto;margin:12px 0;font:12px/1.8 Consolas,monospace}.dialog-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}#confirm-delete{background:var(--bad);color:white;border-color:var(--bad)}
@media(max-width:720px){main{padding:20px 14px 32px}h1{font-size:25px}header{margin-bottom:18px}.toolbar{padding:10px;gap:8px}.toolbar-label{display:none}.toolbar button{flex:1}.panel{padding:16px}.test-layout{grid-template-columns:1fr;gap:18px}.grid{gap:10px}.result{padding:18px}#num{font-size:42px;min-height:56px}.history-actions{gap:6px}td,th{padding:11px 9px}.section-heading{margin-bottom:16px}}
</style>
<main>
<header><p class="eyebrow">NETWORK PERFORMANCE</p><h1>下行带宽测速</h1><p class="subtitle">选择节点，测量 VPS 到本机的实际下行表现。</p></header>
<nav class="toolbar" aria-label="常用操作">
  <span class="toolbar-label"><span class="dot"></span>本地测速工作台</span>
  <button class="ghost" onclick="location.href='/chart'">历史图表</button>
  <button class="ghost" id="quit" onclick="quit()">退出服务</button>
</nav>
<div class="panel">
  <div class="section-heading"><h2>发起测速</h2><p class="hint">选择预设节点，或手动填写服务器地址。</p></div>
  <div class="test-layout"><div>
  <div id="selwrap" style="display:none">
    <label>预设节点</label>
    <select id="sel"><option value="">— 手动输入或选择节点 —</option></select>
  </div>
  <div class="grid">
    <div id="host"><label>IP / 域名</label><input id="h" placeholder="例: 1.2.3.4" autofocus></div>
    <div><label>端口</label><input id="p" type="number" min="1" max="65535" step="1" value="5201"></div>
    <div><label>时长 / 秒</label><input id="t" type="number" min="1" max="300" step="1" value="10"></div>
    <div><label>并发流</label><input id="P" type="number" min="1" max="32" step="1" value="1"></div>
    <button id="go" onclick="run()">测速</button>
  </div>
  <p id="config-note" role="status" style="color:#b45309;font-size:13px"></p><p id="save-note" role="status" style="color:#b45309;font-size:13px"></p>
  </div><div class="result"><p class="result-label">本次下行结果</p>
  <div id="num"><small>准备就绪<br>填写地址后，点击测速或按回车开始。</small></div>
  <div id="bar"><div id="fill"></div></div><p class="result-foot">自动忽略前 3 秒预热 · 结果以实际测量为准</p></div></div>
</div>
<p class="service-note">VPS 端需运行 iperf3 -s · 关闭网页不会退出服务，请使用顶部“退出服务”。</p>
<div class="panel">
  <h2>测试记录</h2><p class="hint">成功测速历史 · 支持勾选批量删除，删除前自动备份。</p><p id="history-note" role="status" style="color:#b45309;font-size:13px"></p>
  <div class="history-actions" aria-label="记录管理">
    <label><input id="select-all" type="checkbox" onchange="selectPage(this.checked)">本页全选</label>
    <button class="ghost danger" id="delete-selected" onclick="requestDelete([...selected])" disabled>删除所选 (0)</button>
    <button class="ghost" id="refresh-history" onclick="reloadHistory()">刷新记录</button>
    <button class="ghost" id="undo-delete" onclick="undoDelete()" disabled>撤销上次删除</button>
    <button class="ghost" id="prev-page" onclick="changePage(-1)">上一页</button>
    <span id="page-info" role="status"></span>
    <button class="ghost" id="next-page" onclick="changePage(1)">下一页</button>
  </div>
  <p id="delete-note" role="status" class="service-note"></p>
  <div class="table-wrap"><table><thead><tr><th>选择</th><th>时间</th><th>目标</th><th>并发流</th><th>下行 Mbps</th><th>MB/s</th><th>操作</th></tr></thead><tbody id="hist"></tbody></table></div>
</div>
<dialog id="delete-dialog" aria-labelledby="delete-title">
  <h2 id="delete-title">确认删除记录</h2>
  <p id="delete-summary"></p>
  <div id="delete-items"></div>
  <p class="service-note">删除前自动备份原始 CSV。删除后没有新记录或其他变更时，可撤销上次删除。</p>
  <div class="dialog-actions"><button class="ghost" onclick="cancelDelete()">取消</button><button id="confirm-delete" onclick="confirmDelete()">确认删除</button></div>
</dialog>
</main>
<script>
const $=id=>document.getElementById(id);
let NS=[],busy=false,quitting=false,closed=false;
let history=[],page=0,historyBusy=false,undoID='',pendingDelete=[],recordControls=[];
const selected=new Set(),pageSize=100;
async function jsonRequest(path,options){
  const response=await fetch(path,options);
  const data=await response.json();
  if(!response.ok)throw new Error(data.err||('HTTP '+response.status));
  return {data,response};
}
// Store initialization failures as values to avoid unhandled promise rejections.
const session=jsonRequest('/session').then(x=>({token:x.data.token})).catch(error=>({error}));
async function post(path,payload){
  const state=await session;
  if(state.error)throw state.error;
  return jsonRequest(path,{method:'POST',headers:{'X-App-Token':state.token,'Content-Type':'application/json'},body:payload===undefined?undefined:JSON.stringify(payload)});
}
function setBusy(value){
  busy=value;
  ['go','h','p','t','P','sel'].forEach(id=>$(id).disabled=value||quitting||historyBusy);
  syncHistoryControls();
}
function currentRows(){return history.slice(page*pageSize,(page+1)*pageSize)}
function syncHistoryControls(){
  const locked=busy||quitting||historyBusy;
  const rows=currentRows();
  $('select-all').disabled=locked||!rows.length;
  $('select-all').checked=rows.length>0&&rows.every(r=>selected.has(r.id));
  $('select-all').indeterminate=selected.size>0&&!$('select-all').checked;
  $('delete-selected').disabled=locked||!selected.size;
  $('delete-selected').textContent='删除所选 ('+selected.size+')';
  $('refresh-history').disabled=locked;
  $('undo-delete').disabled=locked||!undoID;
  $('prev-page').disabled=locked||page===0;
  $('next-page').disabled=locked||(page+1)*pageSize>=history.length;
  $('page-info').textContent='第 '+(page+1)+' / '+Math.max(1,Math.ceil(history.length/pageSize))+' 页 · '+history.length+' 条成功记录';
  recordControls.forEach(({check,remove,id})=>{check.disabled=locked;remove.disabled=locked;check.checked=selected.has(id)});
}
function selectPage(checked){
  if(busy||historyBusy||quitting)return;
  selected.clear();if(checked)currentRows().forEach(r=>selected.add(r.id));syncHistoryControls();
}
function changePage(delta){
  if(busy||historyBusy||quitting)return;
  page=Math.max(0,Math.min(Math.ceil(history.length/pageSize)-1,page+delta));selected.clear();renderHistory();
}
function renderHistory(){
  page=Math.min(page,Math.max(0,Math.ceil(history.length/pageSize)-1));
  $('hist').replaceChildren();recordControls=[];
  currentRows().forEach(r=>$('hist').appendChild(historyRow(r)));syncHistoryControls();
}
function historyRow(r){
  const tr=document.createElement('tr');
  const selectCell=document.createElement('td'),check=document.createElement('input');
  check.type='checkbox';check.ariaLabel='选择 '+r.t+' '+r.target;
  check.onchange=()=>{if(check.checked)selected.add(r.id);else selected.delete(r.id);syncHistoryControls()};
  selectCell.appendChild(check);tr.appendChild(selectCell);
  [r.t,r.target,r.thr,r.mbps,(r.mbps/8).toFixed(1)].forEach((value,i)=>{
    const td=document.createElement('td');td.textContent=String(value);
    if(i===1)td.title=r.ip;
    if(i===3)td.className='ok';
    tr.appendChild(td);
  });
  const actions=document.createElement('td'),remove=document.createElement('button');
  remove.textContent='删除';remove.className='ghost danger row-delete';remove.onclick=()=>requestDelete([r.id]);
  actions.appendChild(remove);tr.appendChild(actions);recordControls.push({check,remove,id:r.id});
  return tr;
}
async function refreshHistory(){
  const {data,response}=await jsonRequest('/data');
  if(closed)return;
  if(!Array.isArray(data))throw new Error('历史记录格式无效');
  history=data.slice().reverse();selected.clear();renderHistory();
  const warning=response.headers.get('X-Data-Warning');
  $('history-note').textContent=warning?decodeURIComponent(warning.replace(/\+/g,' ')):'';
}
async function reloadHistory(){
  if(busy||historyBusy||quitting)return;
  historyBusy=true;setBusy(busy);
  try{await refreshHistory()}catch(e){if(!closed)$('history-note').textContent='历史读取失败: '+e.message}
  finally{historyBusy=false;if(!closed)setBusy(busy)}
}
const historyReady=refreshHistory().catch(e=>{if(!closed)$('history-note').textContent='历史读取失败: '+e.message});
$('delete-dialog').oncancel=()=>{pendingDelete=[]};
function requestDelete(ids){
  if(busy||historyBusy||quitting||!ids.length)return;
  pendingDelete=ids.slice();
  const items=history.filter(r=>ids.includes(r.id));
  if(items.length!==ids.length)return;
  $('delete-summary').textContent='将删除 '+items.length+' 条记录。重新打开历史图表即可查看更新。';
  $('delete-items').replaceChildren();
  items.forEach(r=>{const line=document.createElement('p');line.textContent=r.t+' · '+r.target+' · '+r.mbps+' Mbps';$('delete-items').appendChild(line)});
  $('delete-dialog').showModal();
}
function cancelDelete(){pendingDelete=[];$('delete-dialog').close()}
async function confirmDelete(){
  if(!pendingDelete.length||busy||historyBusy||quitting)return;
  const ids=pendingDelete.slice();cancelDelete();historyBusy=true;setBusy(busy);
  try{
    const {data}=await post('/history/delete',{ids});
    if(closed)return;
    undoID=data.undo;
    $('delete-note').textContent='已删除 '+data.deleted+' 条。原始备份：'+data.backup;
    try{await refreshHistory()}catch(e){if(!closed)$('history-note').textContent='删除已完成，列表刷新失败，请点击刷新记录: '+e.message}
  }catch(e){if(!closed)$('delete-note').textContent='删除未完成: '+e.message}
  finally{historyBusy=false;if(!closed)setBusy(busy)}
}
async function undoDelete(){
  if(!undoID||busy||historyBusy||quitting)return;
  historyBusy=true;setBusy(busy);
  try{
    await post('/history/undo',{id:undoID});if(closed)return;undoID='';
    $('delete-note').textContent='已撤销上次删除，记录已恢复。';
    try{await refreshHistory()}catch(e){if(!closed)$('history-note').textContent='恢复已完成，列表刷新失败: '+e.message}
  }catch(e){if(!closed)$('delete-note').textContent='无法撤销: '+e.message}
  finally{historyBusy=false;if(!closed)setBusy(busy)}
}
jsonRequest('/nodes').then(({data})=>{
  if(closed)return;
  if(!Array.isArray(data))throw new Error('节点配置必须是数组');
  NS=data;if(!NS.length)return;
  $('selwrap').style.display='';
  NS.forEach((n,i)=>{
    const option=document.createElement('option');option.value=String(i);
    option.textContent=n.name+' - '+n.host;$('sel').appendChild(option);
  });
}).catch(e=>{if(!closed)$('config-note').textContent='节点加载失败: '+e.message});
$('sel').onchange=e=>{
  const n=NS[e.target.value];if(n){$('h').value=n.host;$('p').value=n.port||5201}
};
['h','p'].forEach(id=>$(id).oninput=()=>{$('sel').value=''});
$('h').onkeydown=e=>{if(e.key==='Enter'){e.preventDefault();run()}};
function numberInput(id,fallback,max,label){
  const raw=$(id).value.trim();
  const n=raw===''?fallback:Number(raw);
  if(!Number.isInteger(n)||n<1||n>max)throw new Error(label+'必须为 1–'+max+' 的整数');
  return n;
}
async function run(){
  if(busy||quitting||historyBusy)return;
  let input;
  try{
    input={host:$('h').value.trim(),port:numberInput('p',5201,65535,'端口'),
      t:numberInput('t',10,300,'时长'),P:numberInput('P',1,32,'并发流')};
    if(!input.host)throw new Error('请输入 IP 或域名');
    const selected=NS[$('sel').value];
    input.name=selected&&selected.host===input.host&&Number(selected.port||5201)===input.port?selected.name:'';
  }catch(e){$('num').className='err';$('num').textContent=e.message;return}
  setBusy(true);$('save-note').textContent='';
  $('num').className='wait';$('num').textContent='测速中';
  const small=document.createElement('small');small.textContent=' '+input.t+'s + 3s 预热';$('num').appendChild(small);
  const fill=$('fill');fill.style.transition='none';fill.style.width='0';
  const frame=requestAnimationFrame(()=>{fill.style.transition='width '+(input.t+3)+'s linear';fill.style.width='96%'});
  try{
    // Finish initial history loading before starting so a new result is not duplicated.
    await historyReady;
    const query=new URLSearchParams({host:input.host,port:String(input.port),t:String(input.t),P:String(input.P)});
    const {data}=await post('/test?'+query.toString());
    if(closed)return;
    cancelAnimationFrame(frame);fill.style.transition='width .3s';fill.style.width='100%';
    if(data.ok){
      $('num').className='';$('num').textContent=String(data.mbps);
      const unit=document.createElement('small');unit.textContent=' Mbps';$('num').appendChild(unit);
    }else{$('num').className='err';$('num').textContent='失败: '+data.err}
    $('save-note').textContent=data.saved?'记录已保存至 speedtest_log.csv':(data.saveError||'记录未保存');
    if(data.saved){page=0;try{await refreshHistory()}catch(e){if(!closed)$('history-note').textContent='测速已完成，历史刷新失败: '+e.message}}
  }catch(e){if(closed)return;cancelAnimationFrame(frame);fill.style.transition='none';fill.style.width='0';$('num').className='err';$('num').textContent='请求异常: '+e.message}
  finally{busy=false;if(!closed)setBusy(false)}
}
async function quit(){
  if(historyBusy){$('delete-note').textContent='正在处理历史记录，请完成后再退出。';return}
  if(quitting||!confirm(busy?'正在测速，退出将取消测试。确定退出服务？':'确定关闭测速服务？'))return;
  quitting=true;setBusy(busy);$('quit').disabled=true;
  try{
    await post('/quit');
    closed=true;
    document.body.replaceChildren();
    const message=document.createElement('main');message.style.cssText='text-align:center;padding-top:20vh;color:#6b7a8d';
    message.textContent='已请求退出，服务正在保存记录并关闭，可以关掉此页面。';document.body.appendChild(message);
  }catch(e){quitting=false;setBusy(busy);$('quit').disabled=false;$('save-note').textContent='退出失败: '+e.message}
}
</script>`

const chartHTML = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>测速历史图表</title>
<style>
:root{--ink:#192d3b;--muted:#657b89;--line:#e3ebef;--blue:#087eae;--green:#05977a;--bg:#f3f7f9}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 8% 0%,#e4f4ee,transparent 45%),var(--bg);color:var(--ink);font:14px/1.6 system-ui,"Microsoft YaHei",sans-serif}
main{max-width:1200px;margin:0 auto;padding:32px 24px 48px}header{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:24px}
.eyebrow{font:600 11px/1.5 system-ui;letter-spacing:.18em;color:var(--green);margin:0 0 5px}h1{font-size:28px;letter-spacing:-.03em;margin:0}p{margin:0}.subtitle{color:var(--muted);margin-top:5px}
.actions{display:flex;gap:8px;flex-shrink:0}button,a.button{font:inherit;font-weight:500;text-decoration:none;cursor:pointer;border:1px solid var(--line);border-radius:9px;padding:9px 14px;background:#fff;color:var(--ink);display:inline-flex;align-items:center;justify-content:center;gap:6px}
button:hover,a.button:hover{border-color:var(--blue);color:var(--blue)}button:disabled{opacity:.5;cursor:wait}.primary{background:var(--ink)!important;color:white!important;border-color:var(--ink)!important}:focus-visible{outline:3px solid #79bdd8;outline-offset:3px}
.panel{background:white;border:1px solid var(--line);border-radius:16px;box-shadow:0 5px 24px #244b6006}.filters{display:grid;grid-template-columns:2fr 1fr 1fr;gap:16px;padding:18px 22px;margin-bottom:16px}label.field{display:flex;flex-direction:column;gap:6px;font-size:12px;color:var(--muted)}select{font:14px system-ui;color:var(--ink);width:100%;min-width:0;border:1px solid var(--line);border-radius:8px;padding:10px;background:#f8fafb;cursor:pointer}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}.stat{padding:18px 20px;min-width:0}.stat-label{font-size:12px;color:var(--muted)}.stat-value{font:600 29px/1.5 ui-monospace,Consolas,monospace;letter-spacing:-.05em;white-space:nowrap}.stat-value small{font:12px system-ui;letter-spacing:0;color:var(--muted);margin-left:6px}.stat-detail{font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.accent .stat-value{color:var(--green)}
.chart-panel{padding:22px}.chart-heading{display:flex;justify-content:space-between;align-items:center;gap:12px}h2{font-size:17px;margin:0}.hint{font-size:12px;color:var(--muted)}.chart-actions{display:flex;gap:6px;flex-shrink:0}.chart-actions button{font-size:12px;padding:6px 10px}
#series-list{display:flex;flex-wrap:wrap;gap:8px;max-height:132px;overflow:auto;margin:18px 0 8px;padding:2px}.series-chip{display:inline-flex;align-items:center;gap:6px;max-width:100%;border:1px solid var(--line);background:#fafcfd;padding:5px 9px;border-radius:7px;font-size:12px;cursor:pointer}.series-chip span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:220px}.series-chip input{margin:0;accent-color:var(--series-color);cursor:pointer}.series-chip i{width:7px;height:7px;flex-shrink:0;border-radius:50%;background:var(--series-color)}.series-chip:has(input:not(:checked)){opacity:.45}
#c{height:440px;width:100%}#empty{padding:80px 16px;text-align:center;color:var(--muted)}#empty strong{display:block;color:var(--ink);font-size:18px;margin-bottom:8px}.chart-foot{border-top:1px solid var(--line);padding-top:12px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;color:var(--muted);font-size:11px}#warning{color:#a45b18;font-size:12px;margin-bottom:12px;white-space:pre-wrap}#warning:empty{display:none}footer{color:var(--muted);font-size:11px;text-align:center;margin-top:18px}
@media(max-width:720px){main{padding:20px 14px 32px}header{align-items:flex-start;flex-direction:column;gap:14px;margin-bottom:18px}h1{font-size:25px}.actions{width:100%}.actions>*{flex:1}.filters{grid-template-columns:1fr 1fr;padding:16px;gap:12px}.field:first-child{grid-column:1/-1}.stats{grid-template-columns:1fr 1fr;gap:10px}.stat{padding:14px}.stat-value{font-size:25px}.chart-panel{padding:15px}.chart-heading{align-items:flex-start;flex-direction:column}.chart-actions{align-self:flex-end}#c{height:360px}#series-list{max-height:118px}.series-chip span{max-width:175px}}
</style></head>
<body><main>
<header><div><p class="eyebrow">NETWORK PERFORMANCE</p><h1>测速历史</h1><p class="subtitle">查看下行趋势，比较不同节点与并发流的表现。</p></div><div class="actions"><button id="reload" onclick="loadHistory()">刷新数据</button><a class="button primary" href="/">返回测速</a></div></header>
<section class="panel filters" aria-label="图表筛选">
  <label class="field" for="node-filter">节点<select id="node-filter" onchange="renderChart()"><option value="">全部节点</option></select></label>
  <label class="field" for="stream-filter">并发流<select id="stream-filter" onchange="renderChart()"><option value="">全部并发流</option></select></label>
  <label class="field" for="range-filter">时间范围<select id="range-filter" onchange="renderChart()"><option value="all">全部历史</option><option value="7">最近 7 天</option><option value="30">最近 30 天</option><option value="90">最近 90 天</option></select></label>
</section>
<section class="stats" aria-label="当前筛选统计">
  <div class="panel stat"><p class="stat-label">成功测试</p><p class="stat-value" id="stat-count">—</p><p class="stat-detail" id="stat-nodes">等待加载</p></div>
  <div class="panel stat accent"><p class="stat-label">最新一次</p><p class="stat-value"><span id="stat-latest">—</span><small>Mbps</small></p><p class="stat-detail" id="latest-note">—</p></div>
  <div class="panel stat"><p class="stat-label">平均下行</p><p class="stat-value"><span id="stat-average">—</span><small>Mbps</small></p><p class="stat-detail">每次测试等权平均</p></div>
  <div class="panel stat"><p class="stat-label">峰值下行</p><p class="stat-value"><span id="stat-peak">—</span><small>Mbps</small></p><p class="stat-detail" id="peak-note">—</p></div>
</section>
<p id="warning" role="status"></p>
<section class="panel chart-panel">
  <div class="chart-heading"><div><h2>下行带宽趋势</h2><p class="hint" id="scope">正在读取历史记录…</p></div><div class="chart-actions"><button id="show-all" onclick="showAllSeries()">显示全部曲线</button><button id="reset-zoom" onclick="resetZoom()">重置缩放</button></div></div>
  <div id="series-list" aria-label="曲线显示开关"></div>
  <div id="c" role="img" aria-label="按测试时间绘制的下行带宽曲线"></div>
  <div id="empty" role="status" hidden><strong id="empty-title"></strong><p id="empty-detail"></p></div>
  <div class="chart-foot"><span>点击图例显示 / 隐藏 · 拖动底部滑块缩放 · 悬停或轻点数据点查看详情</span><span id="updated">尚未刷新</span></div>
</section>
<footer>相同地址与端口、相同并发流构成一条曲线。连线仅连接离散测量，不代表持续监测。统计基于筛选结果，不随图例或缩放变化。</footer>
</main>
<script src="https://cdn.jsdelivr.net/npm/echarts@5/dist/echarts.min.js"></script>
<script>
const el=id=>document.getElementById(id);
const palette=['#05977a','#087eae','#8b5db4','#d58a16','#d75b77','#548447','#3b68bf','#b36b41','#2d9aa3','#877334','#915b87','#64748b'];
let allRows=[],chart=null,groups=[],colors=new Map(),loading=false;
function seriesKey(r){return JSON.stringify([r.ip,String(r.thr)])}
function selectChartRows(rows,node,streams,days,now){
  const cutoff=days==='all'?-Infinity:now-Number(days)*86400000;
  return rows.filter(r=>(!node||r.ip===node)&&(!streams||String(r.thr)===streams)&&r.time>=cutoff&&(days==='all'||r.time<=now)).slice().sort((a,b)=>a.time-b.time);
}
function groupChartRows(rows){
  const map=new Map();
  rows.forEach(r=>{const key=seriesKey(r);if(!map.has(key))map.set(key,{key,name:r.target,ip:r.ip,streams:String(r.thr),rows:[]});map.get(key).rows.push(r)});
  return [...map.values()].map(g=>({...g,rows:g.rows.slice().sort((a,b)=>a.time-b.time)}));
}
function summarizeChartRows(rows){
  if(!rows.length)return {count:0,nodes:0,latest:null,peak:null,average:0};
  return {count:rows.length,nodes:new Set(rows.map(r=>r.ip)).size,latest:rows.reduce((a,b)=>b.time>=a.time?b:a),peak:rows.reduce((a,b)=>b.mbps>a.mbps?b:a),average:rows.reduce((sum,r)=>sum+r.mbps,0)/rows.length};
}
function setOptions(id,items,initial){
  const select=el(id),old=select.value;select.replaceChildren();
  for(const [value,label] of [['',initial],...items]){const option=document.createElement('option');option.value=value;option.textContent=label;select.appendChild(option)}
  select.value=items.some(x=>x[0]===old)?old:'';
}
function setEmpty(title,detail){el('empty').hidden=false;el('empty-title').textContent=title;el('empty-detail').textContent=detail;el('c').style.display='none'}
function showAllSeries(){if(!chart)return;document.querySelectorAll('#series-list input').forEach(input=>{input.checked=true;chart.dispatchAction({type:'legendSelect',name:input.value})})}
function resetZoom(){if(chart)chart.dispatchAction({type:'dataZoom',start:0,end:100})}
function renderChart(){
  const rows=selectChartRows(allRows,el('node-filter').value,el('stream-filter').value,el('range-filter').value,Date.now());
  const stats=summarizeChartRows(rows);groups=groupChartRows(rows);
  el('stat-count').textContent=String(stats.count);el('stat-nodes').textContent=stats.nodes+' 个节点 · '+groups.length+' 条曲线';
  el('stat-latest').textContent=stats.latest?stats.latest.mbps.toFixed(1):'—';
  el('latest-note').textContent=stats.latest?stats.latest.t+' · '+stats.latest.target:'当前筛选无记录';el('latest-note').title=el('latest-note').textContent;
  el('stat-average').textContent=stats.count?stats.average.toFixed(1):'—';el('stat-peak').textContent=stats.peak?stats.peak.mbps.toFixed(1):'—';
  el('peak-note').textContent=stats.peak?stats.peak.target+' · '+stats.peak.thr+' 流':'—';el('peak-note').title=el('peak-note').textContent;
  el('scope').textContent=rows.length?rows[0].t+' — '+rows[rows.length-1].t:'仅展示成功测试记录';
  el('series-list').replaceChildren();
  el('show-all').disabled=!rows.length;el('reset-zoom').disabled=!rows.length;
  if(!rows.length){if(chart)chart.clear();setEmpty(allRows.length?'这个范围内没有记录':'还没有成功的测试记录',allRows.length?'试试其他节点、并发流或时间范围。':'返回测速页面，完成一次测试后刷新这里。');return}
  if(typeof echarts==='undefined'){setEmpty('图表组件未能加载','统计数据已显示。请检查网络后重新加载页面，图表组件目前通过 CDN 加载。');el('show-all').disabled=true;el('reset-zoom').disabled=true;return}
  el('empty').hidden=true;el('c').style.display='';if(!chart)chart=echarts.init(el('c'));
  groups.forEach(g=>{
    const chip=document.createElement('label');chip.className='series-chip';chip.style.setProperty('--series-color',colors.get(g.key));chip.title=g.name+' · '+g.ip+' · '+g.streams+' 流';
    const input=document.createElement('input');input.type='checkbox';input.checked=true;input.value=g.key;input.ariaLabel='显示 '+chip.title;
    input.onchange=()=>chart.dispatchAction({type:input.checked?'legendSelect':'legendUnSelect',name:g.key});
    const dot=document.createElement('i'),name=document.createElement('span');name.textContent=g.name+' · '+g.streams+' 流';
    chip.appendChild(input);chip.appendChild(dot);chip.appendChild(name);el('series-list').appendChild(chip);
  });
  chart.setOption({animationDuration:250,textStyle:{fontFamily:'system-ui, Microsoft YaHei'},legend:{show:false,data:groups.map(g=>g.key)},
    tooltip:{trigger:'item',confine:true,renderMode:'richText',backgroundColor:'#fff',borderColor:'#dce7ec',textStyle:{color:'#192d3b',fontSize:12},formatter:p=>{const g=groups[p.seriesIndex],r=g.rows[p.dataIndex];return r.target+' · '+r.thr+' 流\n'+r.ip+'\n'+r.t+'\n下行 '+r.mbps.toFixed(1)+' Mbps  /  '+(r.mbps/8).toFixed(1)+' MB/s'}},
    grid:{left:16,right:20,top:35,bottom:78,containLabel:true},
    xAxis:{type:'time',axisLine:{lineStyle:{color:'#dce7ec'}},axisTick:{show:false},axisLabel:{color:'#718592',hideOverlap:true,fontSize:11},splitNumber:window.innerWidth<600?3:6},
    yAxis:{type:'value',min:0,name:'Mbps',nameTextStyle:{color:'#718592',align:'left'},axisLabel:{color:'#718592',fontSize:11},splitLine:{lineStyle:{color:'#edf2f5',type:'dashed'}}},
    dataZoom:[{type:'inside',zoomOnMouseWheel:'ctrl',moveOnMouseWheel:false},{type:'slider',height:24,bottom:16,borderColor:'#e3ebef',backgroundColor:'#f6f9fb',fillerColor:'#087eae15',handleStyle:{color:'#087eae'},textStyle:{color:'#718592'},start:0,end:100}],
    series:groups.map(g=>({name:g.key,type:'line',smooth:false,showSymbol:true,symbol:'circle',symbolSize:6,clip:true,lineStyle:{width:2,opacity:.65},itemStyle:{color:colors.get(g.key)},emphasis:{focus:'series',lineStyle:{width:3,opacity:1}},data:g.rows.map(r=>[r.time,r.mbps])}))
  },true);chart.resize();
}
async function loadHistory(){
  if(loading)return;loading=true;el('reload').disabled=true;el('reload').textContent='读取中…';
  try{
    const response=await fetch('/data'),data=await response.json();if(!response.ok)throw new Error(data.err||'历史读取失败');if(!Array.isArray(data))throw new Error('历史格式无效');
    allRows=data.map(r=>({...r,time:new Date(r.t.replace(' ','T')).getTime()})).filter(r=>Number.isFinite(r.time)&&Number.isFinite(r.mbps));
    const keys=[...new Set(allRows.map(seriesKey))].sort();colors=new Map(keys.map((key,i)=>[key,i<palette.length?palette[i]:'hsl('+((i*137.508)%360)+',58%,44%)']));
    const nodes=new Map();allRows.forEach(r=>nodes.set(r.ip,r.target));
    setOptions('node-filter',[...nodes].sort((a,b)=>a[1].localeCompare(b[1])).map(([ip,name])=>[ip,name===ip?ip:name+' · '+ip]),'全部节点');
    setOptions('stream-filter',[...new Set(allRows.map(r=>String(r.thr)))].sort((a,b)=>Number(a)-Number(b)).map(n=>[n,n+' 流']),'全部并发流');
    const warning=response.headers.get('X-Data-Warning');el('warning').textContent=warning?decodeURIComponent(warning.replace(/\+/g,' ')):'';
    renderChart();el('updated').textContent='更新于 '+new Date().toLocaleTimeString('zh-CN',{hour12:false});
  }catch(e){el('warning').textContent='刷新失败：'+e.message;if(!allRows.length)setEmpty('暂时无法读取历史','请确认测速服务仍在运行，然后点击“刷新数据”。');else el('warning').textContent+='。当前显示上次成功读取的数据。'}
  finally{loading=false;el('reload').disabled=false;el('reload').textContent='刷新数据'}
}
addEventListener('resize',()=>{if(chart){chart.setOption({xAxis:{splitNumber:window.innerWidth<600?3:6}});chart.resize()}});
loadHistory();
</script></body></html>
`

// This example builds a static linux/riscv64 or freebsd/riscv64 Go workload
// that exercises filesystem access, loopback networking, parsing, sorting,
// compression, hashing, and goroutines.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"sync"
	"syscall"
	"time"
)

type record struct {
	Name  string `json:"name"`
	Score int    `json:"score"`
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "--process-child" {
		processChild()
		return
	}

	const input = `[
		{"name":"alpha","score":17},
		{"name":"bravo","score":23},
		{"name":"charlie","score":31},
		{"name":"delta","score":42},
		{"name":"echo","score":29}
	]`

	var records []record
	if err := json.Unmarshal([]byte(input), &records); err != nil {
		panic(err)
	}

	sort.Slice(records, func(left, right int) bool {
		return records[left].Score > records[right].Score
	})

	total := 0
	var digestInput bytes.Buffer
	for _, item := range records {
		total += item.Score
		fmt.Fprintf(&digestInput, "%s:%d;", item.Name, item.Score)
	}

	digest := sha256.Sum256(digestInput.Bytes())
	compressedSize := gzipSize(digestInput.Bytes())
	workerTotal := workerSum(records)
	filesystemProbe()
	filesystemMutationProbe()
	networkProbe()
	processProbe()

	fmt.Printf("records=%d\n", len(records))
	fmt.Printf("top=%s:%d\n", records[0].Name, records[0].Score)
	fmt.Printf("total=%d\n", total)
	fmt.Printf("worker-total=%d\n", workerTotal)
	fmt.Printf("gzip-bytes=%d\n", compressedSize)
	fmt.Printf("sha256=%s\n", hex.EncodeToString(digest[:]))
	fmt.Println("filesystem-ok")
	fmt.Println("network-ok")
	fmt.Println("process-ok")
	fmt.Println("go-showcase-ok")
}

func processChild() {
	if os.Getenv("JRISCV_PROCESS_TOKEN") != "fork-exec-wait" {
		fmt.Fprintln(os.Stderr, "unexpected process token")
		os.Exit(8)
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "query executable path: %v\n", err)
		os.Exit(8)
	}
	if executable != "/showcase" {
		fmt.Fprintf(os.Stderr, "unexpected executable path: %q\n", executable)
		os.Exit(8)
	}
	fmt.Println("process-child-ok")
	os.Exit(7)
}

func processProbe() {
	if len(os.Args) < 2 {
		panic("missing guest executable path")
	}

	command := exec.Command(os.Args[1], "--process-child")
	command.Env = append(os.Environ(), "JRISCV_PROCESS_TOKEN=fork-exec-wait")
	output, err := command.CombinedOutput()
	exitError, ok := err.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 7 {
		panic(fmt.Errorf("unexpected child result: error=%v output=%q", err, output))
	}
	if string(output) != "process-child-ok\n" {
		panic(fmt.Errorf("unexpected child output: %q", output))
	}
}

func networkProbe() {
	tcpProbe()
	udpProbe()
}

func tcpProbe() {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.Close()
		if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			serverResult <- err
			return
		}

		request := make([]byte, len("tcp-request"))
		if _, err := io.ReadFull(connection, request); err != nil {
			serverResult <- err
			return
		}
		if string(request) != "tcp-request" {
			serverResult <- fmt.Errorf("unexpected TCP request: %q", request)
			return
		}
		_, err = connection.Write([]byte("tcp-response"))
		serverResult <- err
	}()

	connection, err := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
	if err != nil {
		panic(err)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = connection.Close()
		panic(err)
	}
	if _, err := connection.Write([]byte("tcp-request")); err != nil {
		_ = connection.Close()
		panic(err)
	}
	response := make([]byte, len("tcp-response"))
	if _, err := io.ReadFull(connection, response); err != nil {
		_ = connection.Close()
		panic(err)
	}
	if err := connection.Close(); err != nil {
		panic(err)
	}
	if string(response) != "tcp-response" {
		panic(fmt.Errorf("unexpected TCP response: %q", response))
	}
	if err := <-serverResult; err != nil {
		panic(err)
	}
}

func udpProbe() {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		panic(err)
	}

	serverResult := make(chan error, 1)
	go func() {
		request := make([]byte, len("udp-request"))
		count, clientAddress, err := server.ReadFrom(request)
		if err != nil {
			serverResult <- err
			return
		}
		if string(request[:count]) != "udp-request" {
			serverResult <- fmt.Errorf("unexpected UDP request: %q", request[:count])
			return
		}
		_, err = server.WriteTo([]byte("udp-response"), clientAddress)
		serverResult <- err
	}()

	connection, err := net.DialTimeout("udp4", server.LocalAddr().String(), 5*time.Second)
	if err != nil {
		panic(err)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = connection.Close()
		panic(err)
	}
	if _, err := connection.Write([]byte("udp-request")); err != nil {
		_ = connection.Close()
		panic(err)
	}
	response := make([]byte, len("udp-response"))
	count, err := connection.Read(response)
	if err != nil {
		_ = connection.Close()
		panic(err)
	}
	if err := connection.Close(); err != nil {
		panic(err)
	}
	if string(response[:count]) != "udp-response" {
		panic(fmt.Errorf("unexpected UDP response: %q", response[:count]))
	}
	if err := <-serverResult; err != nil {
		panic(err)
	}
}

func filesystemProbe() {
	entries, err := os.ReadDir(".")
	if err != nil {
		panic(err)
	}
	if len(entries) == 0 {
		panic("working directory is empty")
	}

	info, err := os.Stat(".")
	if err != nil {
		panic(err)
	}
	if !info.IsDir() {
		panic("working directory is not a directory")
	}

	directory, err := os.Open(".")
	if err != nil {
		panic(err)
	}
	defer directory.Close()

	info, err = directory.Stat()
	if err != nil {
		panic(err)
	}
	if !info.IsDir() {
		panic("opened working directory is not a directory")
	}

	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(".", &filesystem); err != nil {
		panic(err)
	}
	if filesystem.Bsize == 0 || filesystem.Blocks == 0 {
		panic("path filesystem metadata is empty")
	}
	if err := syscall.Fstatfs(int(directory.Fd()), &filesystem); err != nil {
		panic(err)
	}
	if filesystem.Bsize == 0 || filesystem.Blocks == 0 {
		panic("descriptor filesystem metadata is empty")
	}
}

func filesystemMutationProbe() {
	const workspace = ".jriscv-go-showcase-work"
	const original = workspace + "/original.txt"
	const renamed = workspace + "/renamed.txt"
	const hardLink = workspace + "/hard-link.txt"
	const symbolicLink = workspace + "/symbolic-link.txt"

	if err := os.RemoveAll(workspace); err != nil {
		panic(err)
	}
	if err := os.Mkdir(workspace, 0o750); err != nil {
		panic(err)
	}
	cleanupRequired := true
	defer func() {
		if cleanupRequired {
			_ = os.RemoveAll(workspace)
		}
	}()

	file, err := os.OpenFile(original, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o640)
	if err != nil {
		panic(err)
	}
	if _, err := file.WriteString("filesystem-data"); err != nil {
		_ = file.Close()
		panic(err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		panic(err)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
	if err := os.Chmod(workspace, 0o700); err != nil {
		panic(err)
	}
	if err := os.Rename(original, renamed); err != nil {
		panic(err)
	}
	timestamp := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(renamed, timestamp, timestamp); err != nil {
		panic(err)
	}
	if err := os.Link(renamed, hardLink); err != nil {
		panic(err)
	}
	if err := os.Symlink("renamed.txt", symbolicLink); err != nil {
		panic(err)
	}

	data, err := os.ReadFile(renamed)
	if err != nil {
		panic(err)
	}
	if string(data) != "filesystem-data" {
		panic("renamed file content changed")
	}
	data, err = os.ReadFile(hardLink)
	if err != nil {
		panic(err)
	}
	if string(data) != "filesystem-data" {
		panic("hard-linked file content changed")
	}
	data, err = os.ReadFile(symbolicLink)
	if err != nil {
		panic(err)
	}
	if string(data) != "filesystem-data" {
		panic("symbolic-linked file content changed")
	}
	target, err := os.Readlink(symbolicLink)
	if err != nil {
		panic(err)
	}
	if target != "renamed.txt" {
		panic("symbolic link target changed")
	}
	linkInfo, err := os.Lstat(symbolicLink)
	if err != nil {
		panic(err)
	}
	if linkInfo.Mode()&os.ModeSymlink == 0 {
		panic("symbolic link metadata was not preserved")
	}
	info, err := os.Stat(renamed)
	if err != nil {
		panic(err)
	}
	if info.Mode().Perm() != 0o600 {
		panic("file mode change was not preserved")
	}
	if info.ModTime().Unix() != timestamp.Unix() {
		panic("file modification time change was not preserved")
	}
	entries, err := os.ReadDir(workspace)
	if err != nil {
		panic(err)
	}
	if len(entries) != 3 ||
		entries[0].Name() != "hard-link.txt" ||
		entries[1].Name() != "renamed.txt" ||
		entries[2].Name() != "symbolic-link.txt" {
		panic("mutated directory contents are unexpected")
	}

	if err := os.Remove(symbolicLink); err != nil {
		panic(err)
	}
	if err := os.Remove(hardLink); err != nil {
		panic(err)
	}
	if err := os.Remove(renamed); err != nil {
		panic(err)
	}
	if err := os.Remove(workspace); err != nil {
		panic(err)
	}
	cleanupRequired = false
}

func gzipSize(data []byte) int {
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(data); err != nil {
		panic(err)
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	return output.Len()
}

func workerSum(records []record) int {
	results := make(chan int, len(records))
	var group sync.WaitGroup
	for _, item := range records {
		item := item
		group.Add(1)
		go func() {
			defer group.Done()
			results <- item.Score * item.Score
		}()
	}
	group.Wait()
	close(results)

	total := 0
	for value := range results {
		total += value
	}
	return total
}

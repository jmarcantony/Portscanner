package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	reset  = "\u001b[0m"
	yellow = "\u001b[33m"
	cyan   = "\u001b[36m"
	blue   = "\u001b[34m"
	green  = "\u001b[32m"
	red    = "\u001b[31m"
	white  = "\u001b[37m"
)

var (
	wg        sync.WaitGroup
	mu        sync.Mutex
	openPorts int
	timeout   *int    = flag.Int("t", 1, "timeout in seconds")
	start     *int    = flag.Int("s", 1, "starting port to scan from")
	end       *int    = flag.Int("e", 1000, "ending port to scan from")
	host      *string = flag.String("h", "localhost", "host to scan")
	protocol  *string = flag.String("p", "tcp", "protocol to scan")
)

func main() {
	flag.Usage = func() {
		fmt.Printf("%s", white)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Printf("%s", reset)
	}
	flag.Parse()
	s := time.Now()
	fmt.Println(yellow + "\n[*] Starting Scan..." + reset)
	fmt.Printf("\n%sShowing results for %s\n", cyan, *host)
	fmt.Printf("---------------------------------%s\n\n", reset)
	for i := 1; i <= *end; i++ {
		wg.Add(1)
		port := strconv.Itoa(i)
		go scan(&port)
	}
	wg.Wait()
	if openPorts == 0 {
		fmt.Println(red + "[-] No ports were found open!" + reset)
	}
	fmt.Printf("\n%s[*] %d ports were found open in port range %d - %d%s\n", yellow, openPorts, *start, *end, reset)
	fmt.Printf("%s[*] Scan completed in %v%s\n", yellow, time.Since(s), yellow)
}

func scan(port *string) {
	defer wg.Done()
	mu.Lock()
	conn, err := net.DialTimeout(*protocol, *host+":"+*port, time.Second*time.Duration(*timeout))
	mu.Unlock()
	if err != nil {
		return
	}
	defer conn.Close()
	service := getService(port)
	fmt.Printf("%s[+] Open Port: %s%s%s%s|%s   Service: %s\n", blue, green, *port, strings.Repeat(" ", 6-len(*port)), cyan, blue, service)
	mu.Lock()
	openPorts++
	mu.Unlock()
}

func getService(port *string) string {
	cmd := fmt.Sprintf(`exec('''import socket\ntry:\n print(socket.getservbyport(%s, '%s'))\nexcept: print('unknown')''')`, *port, *protocol)
	out, err := exec.Command("python3", "-c", cmd).CombinedOutput()
	if err != nil {
		return "unknown"
	}
	service := strings.TrimSpace(string(out))
	if service != "unknown" {
		service = green + service + reset
	} else {
		service = red + service + reset
	}
	return service
}

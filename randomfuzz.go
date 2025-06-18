package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type customheaders []string

func (h *customheaders) String() string {
	return "Custom headers"
}

func (h *customheaders) Set(val string) error {
	*h = append(*h, val)
	return nil
}

var (
	headers     customheaders
	paramFile  string
	paramCount int
	payload    string
	proxy      string
	onlyPOC    bool
	paramList  []string
)

func init() {
	flag.IntVar(&paramCount, "params", 0, "Number of parameters to use")
	flag.StringVar(&paramFile, "lp", "", "Path to parameter list file")
	flag.StringVar(&payload, "payload", "", "Payload to inject")
	flag.StringVar(&payload, "p", "", "Payload to inject")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL")
	flag.StringVar(&proxy, "x", "", "Proxy URL")
	flag.BoolVar(&onlyPOC, "only-poc", false, "Show only PoC output")
	flag.BoolVar(&onlyPOC, "s", false, "Show only PoC output")
	flag.Var(&headers, "H", "Add headers")
	flag.Var(&headers, "headers", "Add headers")
	flag.Usage = usage
}

func usage() {
	fmt.Println(`
 _____ _     _
|  _  |_|___|_|_ _ ___ ___
|     | |  _| |_'_|_ -|_ -|
|__|__|_|_| |_|_,_|___|___|

Usage:
  -lp       List of parameters in txt file
  -params   Number of parameters to inject
  -payload  Payload to test
  -proxy    Proxy address
  -H        Headers
  -s        Show only PoC
  `)
}

func main() {
	flag.Parse()

	if paramFile != "" {
		params, err := readParamFile(paramFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read param file:", err)
			os.Exit(1)
		}
		paramList = params
	}

	stdin := bufio.NewScanner(os.Stdin)
	targets := make(chan string)
	var wg sync.WaitGroup
	concurrency := 50

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targets {
				res := testURL(target)
				if res != "ERROR" {
					fmt.Println(res)
				}
			}
		}()
	}

	visited := make(map[string]bool)
	for stdin.Scan() {
		url := stdin.Text()
		if !visited[url] {
			targets <- url
			visited[url] = true
		}
	}

	close(targets)
	wg.Wait()
}

func readParamFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var params []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			params = append(params, line)
		}
	}
	return params, scanner.Err()
}

func getRandomParams(params []string, count int) []string {
	if count >= len(params) {
		return params
	}
	r := make([]string, len(params))
	copy(r, params)
	rand.Shuffle(len(r), func(i, j int) { r[i], r[j] = r[j], r[i] })
	return r[:count]
}

func testURL(base string) string {
	if len(paramList) == 0 || paramCount <= 0 || payload == "" {
		return "ERROR"
	}

	u, err := url.Parse(base)
	if err != nil {
		return "ERROR"
	}

	q := url.Values{}
	for _, p := range getRandomParams(paramList, paramCount) {
		q.Set(p, payload)
	}
	u.RawQuery = q.Encode()

	client := buildClient()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "ERROR"
	}
	applyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return "ERROR"
	}
	defer resp.Body.Close()

	if !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return "ERROR"
	}

	body, _ := ioutil.ReadAll(resp.Body)
	if strings.Contains(string(body), payload) {
		if onlyPOC {
			return u.String()
		}
		return "\033[1;31mVulnerable - " + u.String() + "\033[0;0m"
	}

	if onlyPOC {
		return "ERROR"
	}
	return "\033[1;30mNot Vulnerable - " + u.String() + "\033[0;0m"
}

func buildClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
	}
	if proxy != "" {
		if parsedProxy, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(parsedProxy)
		}
	}
	return &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
	}
}

func applyHeaders(req *http.Request) {
	req.Header.Set("Connection", "close")
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
}

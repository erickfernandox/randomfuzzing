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
	paramFile   string
	paramCount  int
	payload     string
	proxy       string
	matchStr    string
	onlyPOC     bool
	paramList   []string
	concurrency int
	htmlOnly    bool
	methodMode  string // new: -o get|post
)

func init() {
	flag.IntVar(&paramCount, "params", 0, "Number of parameters to use")
	flag.StringVar(&paramFile, "lp", "", "Path to parameter list file")
	flag.StringVar(&payload, "payload", "", "Payload to inject")
	flag.StringVar(&payload, "p", "", "Payload to inject (shorthand)")
	flag.StringVar(&matchStr, "match", "", "String to match in response body")
	flag.StringVar(&matchStr, "m", "", "String to match in response body (shorthand)")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL")
	flag.StringVar(&proxy, "x", "", "Proxy URL (shorthand)")
	flag.BoolVar(&onlyPOC, "only-poc", false, "Show only PoC output")
	flag.BoolVar(&onlyPOC, "s", false, "Show only PoC output (shorthand)")
	flag.BoolVar(&htmlOnly, "html", false, "Only match responses with Content-Type: text/html")
	flag.Var(&headers, "H", "Add headers")
	flag.Var(&headers, "headers", "Add headers")
	flag.IntVar(&concurrency, "t", 50, "Number of concurrent threads (min 15)")
	flag.StringVar(&methodMode, "o", "", "Only run one method: get | post (default: both)")
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
  -payload  Payload to test (or -p)
  -match    String to match in response body (or -m)
  -proxy    Proxy address (or -x)
  -H        Headers
  -s        Show only PoC
  -html     Only match if response is HTML
  -t        Number of threads (default 50, minimum 15)
  -o        Only method: get | post (if omitted, tests both)
  `)
}

func main() {
	flag.Parse()

	// validate concurrency minimum
	if concurrency < 15 {
		concurrency = 15
	}

	// validate methodMode if provided
	if methodMode != "" {
		m := strings.ToLower(methodMode)
		if m != "get" && m != "post" {
			fmt.Fprintln(os.Stderr, "Invalid -o value. Use 'get' or 'post'.")
			os.Exit(1)
		}
		methodMode = m
	}

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

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targets {
				results := testMethods(target, methodMode)
				for _, res := range results {
					if res != "ERROR" {
						fmt.Println(res)
					}
				}
			}
		}()
	}

	visited := make(map[string]bool)
	for stdin.Scan() {
		u := strings.TrimSpace(stdin.Text())
		if u == "" {
			continue
		}
		if !visited[u] {
			targets <- u
			visited[u] = true
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

// testMethods executes GET and/or POST depending on methodMode:
// methodMode == "get"  -> only GET
// methodMode == "post" -> only POST
// methodMode == ""     -> both
func testMethods(base string, methodMode string) []string {
	if len(paramList) == 0 || paramCount <= 0 || payload == "" || matchStr == "" {
		return []string{"ERROR"}
	}

	selectedParams := getRandomParams(paramList, paramCount)
	client := buildClient()
	var results []string

	// If methodMode allows GET
	if methodMode == "" || methodMode == "get" {
		getURL, err := url.Parse(base)
		if err != nil {
			// if parsing fails, skip GET but continue with POST if applicable
		} else {
			q := url.Values{}
			for _, p := range selectedParams {
				q.Set(p, payload)
			}
			getURL.RawQuery = q.Encode()

			getReq, err := http.NewRequest("GET", getURL.String(), nil)
			if err == nil {
				applyHeaders(getReq)

				getResp, err := client.Do(getReq)
				if err == nil {
					defer getResp.Body.Close()
					body, _ := ioutil.ReadAll(getResp.Body)

					if !htmlOnly || strings.Contains(getResp.Header.Get("Content-Type"), "text/html") {
						if strings.Contains(string(body), matchStr) {
							if onlyPOC {
								results = append(results, getURL.String())
							} else {
								results = append(results, "\033[1;31mGET Vulnerable - "+getURL.String()+"\033[0;0m")
							}
						} else if !onlyPOC {
							results = append(results, "\033[1;30mGET Not Vulnerable - "+getURL.String()+"\033[0;0m")
						}
					}
				}
			}
		}
	}

	// If methodMode allows POST
	if methodMode == "" || methodMode == "post" {
		postURL, err := url.Parse(base)
		if err != nil {
			// if parsing fails and we already returned results for GET, just return them
			return results
		}
		postData := url.Values{}
		for _, p := range selectedParams {
			postData.Set(p, payload)
		}

		postReq, err := http.NewRequest("POST", postURL.String(), strings.NewReader(postData.Encode()))
		if err == nil {
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			applyHeaders(postReq)

			postResp, err := client.Do(postReq)
			if err == nil {
				defer postResp.Body.Close()
				body, _ := ioutil.ReadAll(postResp.Body)

				if !htmlOnly || strings.Contains(postResp.Header.Get("Content-Type"), "text/html") {
					if strings.Contains(string(body), matchStr) {
						if onlyPOC {
							results = append(results, postURL.String())
						} else {
							results = append(results,
								fmt.Sprintf("\033[1;31mPOST Vulnerable - %s [?%s]\033[0;0m",
									postURL.String(), postData.Encode()))
						}
					} else if !onlyPOC {
						results = append(results,
							fmt.Sprintf("\033[1;30mPOST Not Vulnerable - %s [?%s]\033[0;0m",
								postURL.String(), postData.Encode()))
					}
				}
			}
		}
	}

	return results
}

func buildClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
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

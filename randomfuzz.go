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
	headers       customheaders
	paramFile     string
	paramCount    int
	payload       string
	proxy         string
	matchStr      string
	onlyPOC       bool
	paramList     []string
	concurrency   int
	htmlOnly      bool
	clusterRepeat int
)

func init() {
	flag.IntVar(&paramCount, "params", 0, "Number of parameters to inject")
	flag.StringVar(&paramFile, "lp", "", "Path to parameter list file")
	flag.StringVar(&payload, "payload", "", "Payload to inject")
	flag.StringVar(&payload, "p", "", "Payload to inject")
	flag.StringVar(&matchStr, "match", "", "String to match in response body")
	flag.StringVar(&matchStr, "m", "", "String to match in response body")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL")
	flag.StringVar(&proxy, "x", "", "Proxy URL")
	flag.BoolVar(&onlyPOC, "only-poc", false, "Show only PoC output")
	flag.BoolVar(&onlyPOC, "s", false, "Show only PoC output")
	flag.BoolVar(&htmlOnly, "html", false, "Only match responses with Content-Type: text/html")
	flag.IntVar(&concurrency, "t", 50, "Number of concurrent threads (min 15)")
	flag.IntVar(&clusterRepeat, "q", 1, "Number of clusters to test per URL")
	flag.Var(&headers, "H", "Add headers")
	flag.Var(&headers, "headers", "Add headers")
	flag.Usage = usage
}

func usage() {
	fmt.Println(`

Usage:
  -lp       List of parameters in txt file
  -params   Number of parameters to inject
  -payload  Payload to test
  -match    String to match in response body
  -proxy    Proxy address
  -H        Headers
  -s        Show only PoC
  -html     Only match if response is HTML
  -t        Number of threads (default 50, minimum 15)
  -q        Number of random clusters per URL
`)
}

func main() {
	flag.Parse()

	if concurrency < 15 {
		concurrency = 15
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
				results := testMultipleClusters(target, clusterRepeat)
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

func testMultipleClusters(base string, repeat int) []string {
	var allResults []string
	for i := 0; i < repeat; i++ {
		selectedParams := getRandomParams(paramList, paramCount)
		res := testMethodsWithParams(base, selectedParams)
		allResults = append(allResults, res...)
	}
	return allResults
}

func testMethodsWithParams(base string, selectedParams []string) []string {
	if len(selectedParams) == 0 || payload == "" || matchStr == "" {
		return []string{"ERROR"}
	}

	client := buildClient()
	var results []string

	// GET
	getURL, err := url.Parse(base)
	if err != nil {
		return []string{"ERROR"}
	}
	q := url.Values{}
	for _, p := range selectedParams {
		q.Set(p, payload)
	}
	getURL.RawQuery = q.Encode()

	getReq, err := http.NewRequest("GET", getURL.String(), nil)
	if err != nil {
		return []string{"ERROR"}
	}
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

	// POST
	postURL, err := url.Parse(base)
	if err != nil {
		return results
	}
	postData := url.Values{}
	for _, p := range selectedParams {
		postData.Set(p, payload)
	}

	postReq, err := http.NewRequest("POST", postURL.String(), strings.NewReader(postData.Encode()))
	if err != nil {
		return results
	}
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

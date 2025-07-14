package main

import (
	"bufio"
	"context"
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

	"github.com/chromedp/chromedp"
)

type customheaders []string

func (h *customheaders) String() string       { return "Custom headers" }
func (h *customheaders) Set(val string) error { *h = append(*h, val); return nil }

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
	useHeadless   bool
)

func init() {
	flag.IntVar(&paramCount, "params", 0, "Number of parameters to inject")
	flag.StringVar(&paramFile, "lp", "", "Path to parameter list file")
	flag.StringVar(&payload, "payload", "", "Payload to test")
	flag.StringVar(&payload, "p", "", "Payload to test")
	flag.StringVar(&matchStr, "match", "", "String to match in response body")
	flag.StringVar(&matchStr, "m", "", "String to match in response body")
	flag.StringVar(&proxy, "proxy", "", "Proxy URL")
	flag.StringVar(&proxy, "x", "", "Proxy URL")
	flag.BoolVar(&onlyPOC, "only-poc", false, "Show only PoC output")
	flag.BoolVar(&onlyPOC, "s", false, "Show only PoC output")
	flag.BoolVar(&htmlOnly, "html", false, "Only match responses with Content-Type: text/html")
	flag.IntVar(&concurrency, "t", 50, "Number of concurrent threads (min 15)")
	flag.IntVar(&clusterRepeat, "q", 1, "Number of clusters to test per URL")
	flag.BoolVar(&useHeadless, "headless", false, "Use headless Chrome to verify DOM reflection")
	flag.Var(&headers, "H", "Add headers")
	flag.Usage = usage
}

func usage() {
	fmt.Println("Usage: fuzz -lp params.txt -params 5 -payload \"<script>alert(1)</script>\" -m \"<script>\" -q 3 -headless")
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

	getURL, err := url.Parse(base)
	if err != nil {
		return []string{"ERROR"}
	}
	q := url.Values{}
	for _, p := range selectedParams {
		q.Set(p, payload)
	}
	getURL.RawQuery = q.Encode()

	if useHeadless {
		found, err := runHeadlessCheck(getURL.String(), matchStr)
		if err == nil && found {
			results = append(results, "\033[1;31mHEADLESS GET XSS - "+getURL.String()+"\033[0;0m")
		}
	} else {
		req, _ := http.NewRequest("GET", getURL.String(), nil)
		applyHeaders(req)
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			if !htmlOnly || strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
				if strings.Contains(string(body), matchStr) {
					results = append(results, "\033[1;31mGET Vulnerable - "+getURL.String()+"\033[0;0m")
				}
			}
		}
	}

	return results
}

func runHeadlessCheck(targetURL, match string) (bool, error) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var htmlContent string
	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),
		chromedp.OuterHTML("html", &htmlContent),
	)
	if err != nil {
		return false, err
	}

	return strings.Contains(htmlContent, match), nil
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
	return &http.Client{Transport: transport, Timeout: 6 * time.Second}
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

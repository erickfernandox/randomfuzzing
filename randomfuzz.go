package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

type customheaders []string

func (h *customheaders) String() string       { return "Custom headers" }
func (h *customheaders) Set(val string) error { *h = append(*h, val); return nil }

var (
	headers       customheaders
	paramFile     string
	paramCount    int
	payload       string
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
			// moved browser creation to inside goroutine for thread isolation

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
		res := testWithRod(base, selectedParams)
		allResults = append(allResults, res...)
	}
	return allResults
}

func testWithRod(base string, selectedParams []string) []string {
	if len(selectedParams) == 0 || payload == "" || matchStr == "" {
		return []string{"ERROR"}
	}

	q := url.Values{}
	for _, p := range selectedParams {
		q.Set(p, payload)
	}

	targetURL := base + "?" + q.Encode()
	if useHeadless {
		launcher := launcher.New().NoSandbox(true).MustLaunch()
		browser := rod.New().ControlURL(launcher).MustConnect().MustIgnoreCertErrors(true)
		defer browser.Close()
		// browser is now passed as argument; removed per-instance setup
		page, err := browser.Page(proto.TargetCreateTarget{URL: targetURL})
		if err != nil {
			return []string{"HEADLESS NAVIGATION ERROR - " + targetURL}
		}
		defer page.Close()

		page.MustWaitLoad()
		html, err := page.HTML()
		if err == nil && strings.Contains(html, matchStr) {
			return []string{"\033[1;31mVulnerable - " + targetURL + "\033[0;0m"}
		}
		return []string{"Not Vulnerable - " + targetURL}
	} else {
		resp, err := http.Get(targetURL)
		if err != nil {
			return []string{"ERROR"}
		}
		defer resp.Body.Close()
		body, _ := ioutil.ReadAll(resp.Body)
		if !htmlOnly || strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			if strings.Contains(string(body), matchStr) {
				return []string{"\033[1;31mVulnerable - " + targetURL + "\033[0;0m"}
			}
		}
		return []string{"Not Vulnerable - " + targetURL}
	}
}

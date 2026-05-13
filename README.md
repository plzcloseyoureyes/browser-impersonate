# Browser-Impersonate
[![GoDoc](https://godoc.org/github.com/plzcloseyoureyes/browser-impersonate?status.svg)](https://godoc.org/github.com/plzcloseyoureyes/browser-impersonate)
[![codecov](https://codecov.io/gh/plzcloseyoureyes/browser-impersonate/graph/badge.svg?token=XGHX707RK6)](https://codecov.io/gh/plzcloseyoureyes/browser-impersonate) 
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/plzcloseyoureyes/browser-impersonate/blob/master/LICENSE)
## Browser Impersonate

Browser Impersonate is a lightweight toolkit for crafting HTTP/TLS requests that closely mimic real browser fingerprints, helping developers bypass naive bot detection and reproduce authentic browser network behavior.

Inspired by projects like [curl-impersonate](https://github.com/lwthiker/curl-impersonate), it focuses on realistic TLS handshakes, HTTP/2 behavior, and browser-specific request profiles for scraping, automation, and security research.

# Example
```go
package main

import (
	"fmt"
	"io"
	"log"

	http "github.com/bogdanfinn/fhttp"

	tls_client "github.com/bogdanfinn/tls-client"
	browser_impersonate "github.com/plzcloseyoureyes/browser-impersonate"
)

func main() {
	randomImpersonation := browser_impersonate.GetRandomRealisticImpersonateOption()
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithCookieJar(jar), // create cookieJar instance and pass it as argument
	}
	tclient, err := browser_impersonate.NewImpersonateTLShttpClient(randomImpersonation, tls_client.NewNoopLogger(), options...)

	req, err := http.NewRequest(http.MethodGet, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		log.Println(err)
		return
	}
	resp, err := tclient.Do(req)
	if err != nil {
		log.Println(err)
		return
	}

	defer resp.Body.Close()

	log.Println(fmt.Sprintf("status code: %d", resp.StatusCode))

	readBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println(string(readBytes))
}
```

## IMPORTANT:
build tag of "no_azuretls" will compile without the azuretls support removing it from the final binary file size.
can also be used to eliminate the tls-client usage by building with "no_tlsclient".

- Example:
```bash
go build -tags "no_tlsclient,test" -o final.bin ./
```
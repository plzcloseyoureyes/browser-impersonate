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

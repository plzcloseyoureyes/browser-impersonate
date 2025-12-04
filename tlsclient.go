package browser_impersonate

import (
	"fmt"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
)

// NewImpersonateTLShttpClient is a tls_client.NewHttpClient wrapper, with the option to set emulated device and browser
// will set default request headers, tls fingerprinting, and tls profile of the emulation target.
func NewImpersonateTLShttpClient(impersonateOption ImpersonateOption, logger tls_client.Logger, options ...tls_client.HttpClientOption) (tls_client.HttpClient, error) {
	// setup default headers:
	// &impersonateOption
	newOptions := []tls_client.HttpClientOption{}

	// Headers
	if !impersonateOption.SkipHeaders {
		defaultHeaders := make(fhttp.Header)
		ImpersonateHeaders(defaultHeaders, impersonateOption, true)
		if !impersonateOption.SkipHeaderOrder {
			defaultHeaders[fhttp.HeaderOrderKey] = GetHeaderOrder(impersonateOption)
		}
		newOptions = append(newOptions, tls_client.WithDefaultHeaders(defaultHeaders))
		if defaultHeaders.Get("User-Agent") == "" {
			fmt.Println(impersonateOption)
		}
		//fmt.Println(defaultHeaders)
	}
	// TLS Client Profile:
	switch impersonateOption.Browser.Type {
	case BrowserSafari:
		switch impersonateOption.OS {
		case MacOS:
			// newOptions = append(newOptions, tls_client.WithClientProfile())
		case IOS:
			newOptions = append(newOptions, tls_client.WithClientProfile(Safari_IOS_26))
		}
	case BrowserChrome, BrowserBrave, BrowserEdge:
		newOptions = append(newOptions, tls_client.WithRandomTLSExtensionOrder())
		if impersonateOption.Browser.Type == BrowserChrome && impersonateOption.OS == IOS {
			newOptions = append(newOptions, tls_client.WithClientProfile(Chrome142_IOS_26))
		} else {
			newOptions = append(newOptions, tls_client.WithClientProfile(Chrome141_ClientProfile))
		}
	case BrowserFirefox:
		newOptions = append(newOptions, tls_client.WithClientProfile(FirefoxClientProfile))
	}
	// newOptions = append(newOptions, tls_client.WithDefaultHeaders(fhttp.Header{}))
	finalOpts := append(newOptions, options...)
	newClient, err := tls_client.NewHttpClient(logger, finalOpts...)
	if err == nil {
		// Do something with the client here
	}
	return newClient, err
}

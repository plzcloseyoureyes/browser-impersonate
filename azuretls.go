//go:build !no_azuretls

package browser_impersonate

import (
	"github.com/Noooste/azuretls-client"

	fhttp "github.com/Noooste/fhttp"
)

func NewImpersonateAzureTLSsession(impersonateOption ImpersonateOption) (*azuretls.Session, error) {
	newSession := azuretls.NewSession()
	SetImpersonateAzureTLS(newSession, impersonateOption)
	return newSession, nil
}

// Utility function to set the specific emulation option on a given AzureTLS Sessionxc
func SetImpersonateAzureTLS(session *azuretls.Session, impersonateOption ImpersonateOption) error {
	// Headers
	if !impersonateOption.SkipHeaders {
		defaultHeaders := make(fhttp.Header)
		ImpersonateHeaders(defaultHeaders, impersonateOption, true)
		session.Header = defaultHeaders
	}
	if !impersonateOption.SkipHeaderOrder {
		session.HeaderOrder = GetHeaderOrder(impersonateOption)
	}

	// TlS Fingerprinting:
	switch impersonateOption.Browser.Type {
	case BrowserSafari:
		switch impersonateOption.OS {
		case MacOS:
			session.Browser = azuretls.Safari
			// newOptions = append(newOptions, tls_client.WithClientProfile())
		case IOS:
			session.Browser = azuretls.Ios
		}
	case BrowserChrome, BrowserBrave, BrowserEdge:
		if impersonateOption.Browser.Type == BrowserChrome && impersonateOption.OS == IOS {

			session.Browser = azuretls.Ios
		} else {
			session.Browser = azuretls.Chrome
		}
	case BrowserFirefox:
		session.Browser = azuretls.Firefox
	}
	return nil
}

package browser_impersonate

import (
	"fmt"
	"math/rand"
	"strings"
)

type ImpersonateOS int
type BrowserType string

const (
	BrowserFirefox BrowserType = "firefox"
	BrowserEdge    BrowserType = "edge"
	BrowserBrave   BrowserType = "brave"
	BrowserOpera   BrowserType = "opera"
	BrowserChrome  BrowserType = "chrome"
	BrowserSafari  BrowserType = "safari"
)

const (
	Windows ImpersonateOS = iota
	Linux
	MacOS
	Android
	IOS
)

func (e ImpersonateOS) String() string {
	return []string{"Windows", "Linux", "Mac", "Android", "IOS"}[e]
}

func (e ImpersonateOS) IsMobile() bool {
	return e == IOS || e == Android
}

func (e ImpersonateOS) GetSecChPlatform() string {
	switch e {
	case MacOS:
		return `"macOS"`
	case Linux:
		return `"Linux"`
	case Windows:
		return `"Windows"`
	case Android:
		return `"Android"`
	case IOS:
		return `"iOS"`
	default:
		return `"Windows"`
	}
}

type ImpersonateBrowser struct {
	Type    BrowserType
	Version int // Optional version defaults to latest
}

type ImpersonateOption struct {
	OS                ImpersonateOS
	OverwriteHeaders  map[string]string
	Browser           ImpersonateBrowser
	SkipHeaders       bool
	SkipHTTP2Settings bool
	SkipPHeaderOrder  bool
	SkipHeaderOrder   bool
}

func ImpersonateHeaders(h AnyHttpHeader, impersonateOption ImpersonateOption, isSecureContext bool) {
	hSet := func(key string, value string) {
		dontSetThisHeader := false
		for k := range impersonateOption.OverwriteHeaders {
			if strings.EqualFold(k, key) {
				dontSetThisHeader = true
			}
		}
		if !dontSetThisHeader {
			h.Set(key, value)
		}
	}
	for k, v := range impersonateOption.OverwriteHeaders {
		h.Set(k, v)
	}
	// All browsers send the upgrade-insecure-requests header...
	hSet("Upgrade-Insecure-Requests", "1")
	if !isSecureContext {
		// On insecure context, all browsers seem to share the same encoding options.
		hSet("Accept-Encoding", "gzip, deflate")
	}

	// Just a default accept-language, can be overwritten, and should be.
	hSet("Accept-Language", "en-US,en;q=0.9")
	switch impersonateOption.Browser.Type {
	case BrowserSafari:
		hSet("Priority", "u=0, i")
		hSet("User-Agent", GetSafariUserAgent(impersonateOption.OS))
		hSet("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		if isSecureContext {
			// Accept-Encoding is same on IOS and MacOS
			hSet("Accept-Encoding", "gzip, deflate, br")
		}
		// Safari seems to not send the sec-fetch-user header.
		HeaderSecFetch(h, false)
	case BrowserFirefox:
		hSet("Priority", "u=0, i")
		hSet("te", "trailers")
		hSet("User-Agent", GetFirefoxUserAgent(impersonateOption.OS, impersonateOption.Browser.Version))
		HeaderSecFetch(h, true)
	case BrowserChrome, BrowserBrave, BrowserEdge:
		if isSecureContext {
			hSet("Priority", "u=0, i")
		}

		if impersonateOption.Browser.Version == 0 {
			impersonateOption.Browser.Version = 142
		}

		if impersonateOption.OS == IOS {
			hSet("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			if isSecureContext {
				hSet("Accept-Encoding", "gzip, deflate, br")
			}
		} else {
			hSet("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
			if isSecureContext {
				hSet("Accept-Encoding", "gzip, deflate, br, zstd")
			}
			HeaderChromeSecChUA(h, impersonateOption)
		}
		hSet("Cache-Control", "max-age=0")
		if isSecureContext {
			HeaderSecFetch(h, true)
		}
		if impersonateOption.Browser.Type == BrowserBrave {
			hSet("Sec-Gpc", "1")
		}
		userAgentHeader := ""
		switch impersonateOption.OS {
		case Android:
			userAgentHeader = fmt.Sprintf("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Mobile Safari/537.36", impersonateOption.Browser.Version)
		case IOS:
			userAgentHeader = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_1_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/142.0.7444.46 Mobile/15E148 Safari/604.1"
		case Windows:
			userAgentHeader = fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", impersonateOption.Browser.Version)
		case MacOS:
			userAgentHeader = fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", impersonateOption.Browser.Version)
		}
		if impersonateOption.Browser.Type == BrowserEdge {
			userAgentHeader = userAgentHeader + fmt.Sprintf(" Edg/%d.0.0.0", impersonateOption.Browser.Version)
		}
		hSet("User-Agent", userAgentHeader)
	}
}

func GetHeaderOrder(impersonateOption ImpersonateOption) []string {
	switch impersonateOption.Browser.Type {
	case BrowserFirefox:
		return []string{"User-Agent", "accept", "accept-language", "accept-encoding", "upgrade-insecure-requests", "sec-fecth-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "priority"}
	case BrowserBrave, BrowserChrome, BrowserEdge:
		fallthrough
	default:
		if impersonateOption.OS == IOS {
			//return []string{}
		}
		return []string{"cache-control", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-gpc", "upgrade-insecure-requests", "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language"}
	}
}

func GetSafariUserAgent(os ImpersonateOS) string {
	switch os {
	case MacOS:
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15"
	case IOS:
		// Firefox on iOS uses WebKit engine, not Gecko
		return "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/604.1"
	default:
		return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15"
	}
}
func GetFirefoxUserAgent(os ImpersonateOS, version int) string {
	if version == 0 {
		version = 145
	}
	switch os {
	case Windows:
		return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%d.0) Gecko/20100101 Firefox/%d.0", version, version)
	case MacOS:
		return fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:%d.0) Gecko/20100101 Firefox/%d.0", version, version)
	case Linux:
		return fmt.Sprintf("Mozilla/5.0 (X11; Linux x86_64; rv:%d.0) Gecko/20100101 Firefox/%d.0", version, version)
	case Android:
		return fmt.Sprintf("Mozilla/5.0 (Android 13; Mobile; rv:%d.0) Gecko/%d.0 Firefox/%d.0", version, version, version)
	case IOS:
		// Firefox on iOS uses WebKit engine, not Gecko
		return fmt.Sprintf("Mozilla/5.0 (iPhone; CPU iPhone OS 26_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/%d.0  Mobile/15E148 Safari/604.1", version)
	default:
		return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%d.0) Gecko/20100101 Firefox/%d.0", version, version)
	}
}

var AvailableImpersonateOS = []ImpersonateOS{
	Windows,
	MacOS,
	IOS,
	Android,
}

// Pick random OS impersonation
func GetRandomImpersonateOS() ImpersonateOS {
	return AvailableImpersonateOS[rand.Int()%len(AvailableImpersonateOS)]
}

func GetRandomRealisticImpersonateOption() ImpersonateOption {
	pickedOS := GetRandomImpersonateOS()
	var browserTypeOptions []BrowserType
	switch pickedOS {
	case IOS:
		browserTypeOptions = []BrowserType{BrowserSafari, BrowserChrome}
	case MacOS:
		browserTypeOptions = []BrowserType{BrowserSafari, BrowserBrave, BrowserChrome, BrowserFirefox}
	case Windows:
		browserTypeOptions = []BrowserType{BrowserEdge, BrowserBrave, BrowserChrome, BrowserFirefox}
	case Android:
		browserTypeOptions = []BrowserType{BrowserChrome}
	}
	browserTypePicked := browserTypeOptions[rand.Intn(len(browserTypeOptions))]
	return ImpersonateOption{
		OS: pickedOS,
		Browser: ImpersonateBrowser{
			Type: browserTypePicked,
		},
	}
}

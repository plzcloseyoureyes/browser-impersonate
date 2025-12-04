package browser_impersonate

import "fmt"

type AnyHttpHeader interface {
	Set(key string, value string)
}

// Only relevant to Chromium based browsers anyway.
func BrowserTypeToSecChUaName(browserType BrowserType) string {
	switch browserType {
	case BrowserChrome:
		return "Google Chrome"
	case BrowserBrave:
		return "Brave"
	case BrowserEdge:
		return "Microsoft Edge"
	default:
		return "Google Chrome"
	}
}
func GetSecChUaHeader(browserInfo ImpersonateBrowser) string {
	switch browserInfo.Type {
	case BrowserOpera:
		secChUa := `"Not;A=Brand";v="99", "Opera";v="123", "Chromium";v="139"`
		return secChUa
	default:
		secChUa := fmt.Sprintf(`"Chromium";v="%d", "%s";v="%d", "Not_A Brand";v="99"`,
			browserInfo.Version,
			BrowserTypeToSecChUaName(browserInfo.Type),
			browserInfo.Version,
		)
		return secChUa
	}
}

func HeaderChromeSecChUA(headers AnyHttpHeader, impersonateOption ImpersonateOption) {
	mobile := "?0"
	if impersonateOption.OS.IsMobile() {
		mobile = "?1"
	}

	secChUa := GetSecChUaHeader(impersonateOption.Browser)
	headers.Set("Sec-Ch-Ua", secChUa)
	headers.Set("Sec-Ch-Ua-Mobile", mobile)
	headers.Set("Sec-Ch-Ua-Platform", impersonateOption.OS.GetSecChPlatform())
}

func HeaderSecFetch(headers AnyHttpHeader, includeSecFetchUser bool) {
	headers.Set("Sec-Fetch-Site", "none")
	headers.Set("Sec-Fetch-Mode", "navigate")
	if includeSecFetchUser {
		headers.Set("Sec-Fetch-User", "?1")
	}
	headers.Set("Sec-Fetch-Dest", "document")
}

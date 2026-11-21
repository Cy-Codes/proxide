package portal

import (
	"fmt"
	"net"
	"strings"

	"proxide/internal/model"
)

// DeviceGuide holds pure presentation instructions tailored to a detected device platform.
type DeviceGuide struct {
	Platform      model.DevicePlatform
	DisplayName   string
	PrimaryCAFile string
	PrimaryCAPath string
	Steps         []string
	ADBCommand    string
	ControllerEnv string
	Constraint    string
}

// ClassifyUserAgent maps a raw HTTP User-Agent string purely to a DevicePlatform.
func ClassifyUserAgent(ua string) model.DevicePlatform {
	lower := strings.ToLower(strings.TrimSpace(ua))
	if lower == "" {
		return model.PlatformUnknown
	}

	switch {
	case strings.Contains(lower, "firetv") ||
		strings.Contains(lower, "amazonwebappplatform") ||
		strings.Contains(lower, "aftb") ||
		strings.Contains(lower, "aftm") ||
		strings.Contains(lower, "aftt") ||
		strings.Contains(lower, "afts") ||
		strings.Contains(lower, "aftk") ||
		strings.Contains(lower, "aftn") ||
		(strings.Contains(lower, "silk/") && strings.Contains(lower, "android")):
		return model.PlatformFireTV

	case strings.Contains(lower, "appletv") || strings.Contains(lower, "tvos"):
		return model.PlatformTVOS

	case strings.Contains(lower, "android tv") ||
		strings.Contains(lower, "androidtv") ||
		strings.Contains(lower, "googletv") ||
		strings.Contains(lower, "shield android tv") ||
		strings.Contains(lower, "mibox") ||
		strings.Contains(lower, "bravia") ||
		strings.Contains(lower, "chromecast"):
		return model.PlatformAndroidTV

	case strings.Contains(lower, "iphone") ||
		strings.Contains(lower, "ipad") ||
		strings.Contains(lower, "ipod") ||
		strings.Contains(lower, "cfnetwork"):
		return model.PlatformIOS

	case strings.Contains(lower, "android"):
		return model.PlatformAndroid

	case strings.Contains(lower, "curl/") ||
		strings.Contains(lower, "go-http-client/") ||
		strings.Contains(lower, "python-requests/") ||
		strings.Contains(lower, "python-urllib/") ||
		strings.Contains(lower, "httpie/") ||
		strings.Contains(lower, "node-fetch") ||
		strings.Contains(lower, "undici") ||
		strings.Contains(lower, "axios/") ||
		strings.Contains(lower, "postmanruntime/"):
		return model.PlatformCLIController

	case strings.Contains(lower, "macintosh") ||
		strings.Contains(lower, "windows nt") ||
		strings.Contains(lower, "x11; linux") ||
		strings.Contains(lower, "x11; ubuntu"):
		return model.PlatformDesktop

	default:
		return model.PlatformUnknown
	}
}

// ParsePlatformOverride maps an optional query-string override back to a valid DevicePlatform.
func ParsePlatformOverride(raw string) (model.DevicePlatform, bool) {
	switch model.DevicePlatform(strings.ToLower(strings.TrimSpace(raw))) {
	case model.PlatformFireTV:
		return model.PlatformFireTV, true
	case model.PlatformAndroidTV:
		return model.PlatformAndroidTV, true
	case model.PlatformAndroid:
		return model.PlatformAndroid, true
	case model.PlatformIOS:
		return model.PlatformIOS, true
	case model.PlatformTVOS:
		return model.PlatformTVOS, true
	case model.PlatformCLIController:
		return model.PlatformCLIController, true
	case model.PlatformDesktop:
		return model.PlatformDesktop, true
	default:
		return model.PlatformUnknown, false
	}
}

// BuildDeviceGuide builds deterministic onboarding instructions for the given platform and proxy endpoint.
func BuildDeviceGuide(platform model.DevicePlatform, proxyHost, proxyPort, portalURL string) DeviceGuide {
	hostPort := net.JoinHostPort(proxyHost, proxyPort)
	adbCmd := fmt.Sprintf("adb shell settings put global http_proxy %s", hostPort)
	ctrlEnv := fmt.Sprintf(
		"export HTTP_PROXY=http://%s\nexport HTTPS_PROXY=http://%s\nexport SSL_CERT_FILE=/path/to/proxide-ca.pem\ncurl -H \"X-Proxide-Client: controller-1\" https://example.com",
		hostPort, hostPort,
	)

	switch platform {
	case model.PlatformFireTV:
		return DeviceGuide{
			Platform:      platform,
			DisplayName:   "Amazon Fire TV",
			PrimaryCAFile: "proxide-ca.pem (PEM)",
			PrimaryCAPath: "/ca.pem",
			Steps: []string{
				fmt.Sprintf("Set Wi-Fi manual proxy (or run adb below) to Host %s and Port %s.", proxyHost, proxyPort),
				fmt.Sprintf("Download the CA certificate from %s/ca.pem (or /ca.crt) using Amazon Silk or adb push.", portalURL),
				"Install via Settings -> My Fire TV / Security & Restrictions or Install from Storage, or embed the CA in your debug app's network_security_config.",
			},
			ADBCommand: adbCmd,
			Constraint: "Android/FireOS 7+ release builds ignore user-installed CAs unless the app's network_security_config trusts user certificates. Use debug builds or TLS passthrough for pinned third-party apps.",
		}
	case model.PlatformAndroidTV:
		return DeviceGuide{
			Platform:      platform,
			DisplayName:   "Android TV / Google TV",
			PrimaryCAFile: "proxide-ca.crt (CRT/PEM)",
			PrimaryCAPath: "/ca.crt",
			Steps: []string{
				fmt.Sprintf("Set Wi-Fi proxy (or run adb below) to Host %s and Port %s.", proxyHost, proxyPort),
				fmt.Sprintf("Download %s/ca.crt and install under Settings -> Security & restrictions -> Credential storage -> Install from storage.", portalURL),
			},
			ADBCommand: adbCmd,
			Constraint: "Android 7+ apps only trust user CAs when permitted by network_security_config; third-party pinned apps require TLS passthrough.",
		}
	case model.PlatformAndroid:
		return DeviceGuide{
			Platform:      platform,
			DisplayName:   "Android Mobile",
			PrimaryCAFile: "proxide-ca.crt (CRT)",
			PrimaryCAPath: "/ca.crt",
			Steps: []string{
				fmt.Sprintf("Open Wi-Fi -> Modify network -> Advanced -> Proxy Manual: Host %s, Port %s.", proxyHost, proxyPort),
				fmt.Sprintf("Open %s/ca.crt and install under Settings -> Security -> Encryption & credentials -> Install a certificate -> CA certificate.", portalURL),
			},
			ADBCommand: adbCmd,
			Constraint: "Release APKs without user-CA trust in network_security_config will fail TLS verification; add the domain to Proxide's passthrough list for unowned apps.",
		}
	case model.PlatformIOS:
		return DeviceGuide{
			Platform:      platform,
			DisplayName:   "iOS / iPadOS",
			PrimaryCAFile: "proxide-ca.cer (DER)",
			PrimaryCAPath: "/ca.cer",
			Steps: []string{
				fmt.Sprintf("Download %s/ca.cer in Safari and tap Allow to download the configuration profile.", portalURL),
				"Open Settings -> General -> VPN & Device Management -> Proxide Local Root CA -> Install.",
				"REQUIRED: Open Settings -> General -> About -> Certificate Trust Settings and enable full trust for Proxide Local Root CA.",
				fmt.Sprintf("Open Settings -> Wi-Fi -> (i) -> Configure Proxy -> Manual: Server %s, Port %s.", proxyHost, proxyPort),
			},
			Constraint: "Apps using custom SecTrust certificate pinning must be added to Proxide's TLS passthrough list.",
		}
	case model.PlatformTVOS:
		return DeviceGuide{
			Platform:      platform,
			DisplayName:   "Apple tvOS",
			PrimaryCAFile: "proxide-ca.cer (DER)",
			PrimaryCAPath: "/ca.cer",
			Steps: []string{
				fmt.Sprintf("Download %s/ca.cer on a Mac and install via Apple Configurator (or supervised profile) onto Apple TV.", portalURL),
				"Enable full trust in Settings -> General -> About -> Certificate Trust Settings.",
				fmt.Sprintf("Configure HTTP Proxy manually via Apple Configurator Wi-Fi payload or Network settings to %s:%s.", proxyHost, proxyPort),
			},
			Constraint: "tvOS lacks a web browser; Apple Configurator profile installation is the reliable path for Root CA trust.",
		}
	case model.PlatformCLIController:
		return DeviceGuide{
			Platform:      platform,
			DisplayName:   "Local Controller / CLI Script",
			PrimaryCAFile: "proxide-ca.pem (PEM)",
			PrimaryCAPath: "/ca.pem",
			Steps: []string{
				fmt.Sprintf("Download %s/ca.pem into your local controller environment.", portalURL),
				"Export HTTP_PROXY, HTTPS_PROXY, and SSL_CERT_FILE (or REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS).",
				"Send the X-Proxide-Client header to attribute flows separately per controller instance.",
			},
			ControllerEnv: ctrlEnv,
		}
	default:
		return DeviceGuide{
			Platform:      platform,
			DisplayName:   "All Devices & Local Controllers",
			PrimaryCAFile: "proxide-ca.pem (PEM)",
			PrimaryCAPath: "/ca.pem",
			Steps: []string{
				fmt.Sprintf("Configure HTTP/HTTPS proxy manually to Host %s and Port %s.", proxyHost, proxyPort),
				fmt.Sprintf("Download /ca.cer (Apple iOS/tvOS) or /ca.pem (Android/Fire TV/Linux/Controllers) from %s and verify the SHA-256 fingerprint.", portalURL),
				"Once proxied, you can also revisit this portal anytime at http://proxide.local.",
			},
			ADBCommand:    adbCmd,
			ControllerEnv: ctrlEnv,
			Constraint:    "Roku and cert-pinned apps are best-effort only; use Proxide's TLS passthrough list when an app pins upstream certificates.",
		}
	}
}

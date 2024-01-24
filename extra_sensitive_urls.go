package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)


type urlCheck func(*url.URL) bool

func main() {

	checks := []urlCheck{
		// query string stuff
		func(u *url.URL) bool {

			interesting := 0
			for k, vv := range u.Query() {
				for _, v := range vv {
					if qsCheck(k, v) {
						interesting++
					}
				}
			}
			return interesting > 0
		},

		// extensions
		func(u *url.URL) bool {
			exts := []string{
				".php",
				".phtml",
				".conf",
				".config",
				".db",
				".dbf",
				".mdb",
				".ora",
				".sql", 
				".txt",
				".md",
				".toml",
				".htaccess",
				".vhost",
				".go",
				".nginx",
				".exe",
				".rb",
				".py",
				".sh",
				".cmd",
				".h",
				".git",
				".bak",
				".old",
				".sql",
				".proto",
				".bat",
				".bak",
				".xls",
				".xlsx",
				".csv",
				".asp",
				".aspx",
				".asmx",
				".ashx",
				".cgi",
				".pl",
				".json",
				".xml",
				".rb",
				".py",
				".sh",
				".yaml",
				".yml",
				".toml",
				".ini",
				".md",
				".mkd",
				".do",
				".jsp",
				".env",
				".jspa",
				".dll",
				".jar",
				".war",
				".bat",
				".DS_Store",
				".swp",
				".sln",
				".csproj",
				".vbproj",
				".java",
				".class",
				".ear",
				".jsp",
				".svn",
				".inc"
				
				
			}

			p := strings.ToLower(u.EscapedPath())
			for _, e := range exts {
				if strings.HasSuffix(p, e) {
					return true
				}
			}

			return false
		},

		// path bits
		func(u *url.URL) bool {
			p := strings.ToLower(u.EscapedPath())
			return strings.Contains(p, "ajax") ||
				strings.Contains(p, "jsonp") ||
				strings.Contains(p, "debug") ||
				strings.Contains(p, "phpmyadmin") ||
				strings.Contains(p, "access") ||
				strings.Contains(p, "root") ||
				strings.Contains(p, "internal") ||
				strings.Contains(p, "private") ||
				strings.Contains(p, "secret") ||
				strings.Contains(p, "debug") ||
				strings.Contains(p, "gitlab") ||
				strings.Contains(p, "grafana") ||
				strings.Contains(p, "jenkins") ||
				strings.Contains(p, "jira") ||
				strings.Contains(p, "shell") ||
				strings.Contains(p, "access") ||
				strings.Contains(p, "dbg") ||
				strings.Contains(p, "edit") ||
				strings.Contains(p, "grant") ||
				strings.Contains(p, "filter") ||
				strings.Contains(p, "delete") ||
				strings.Contains(p, "execute") ||
				strings.Contains(p, "load") ||
				strings.Contains(p, "make") ||
				strings.Contains(p, "git") ||
				strings.Contains(p, "bak") ||
				strings.Contains(p, "admin") ||
				strings.Contains(p, "include") ||
				strings.Contains(p, "src") ||
				strings.Contains(p, "redirect") ||
				strings.Contains(p, "proxy") ||
				strings.Contains(p, "test") ||
				strings.Contains(p, "tmp") ||
				strings.Contains(p, "temp") ||
				strings.Contains(p, "admin") ||
                                                                strings.Contains(p, "login") ||
                                                                strings.Contains(p, "logout") ||
                                                                strings.Contains(p, "user/profile") ||
                                                                strings.Contains(p, "api") ||
                                                                strings.Contains(p, "reset-password") ||
                                                                strings.Contains(p, "uploads") ||
                                                                strings.Contains(p, "debug") ||
                                                                strings.Contains(p, "internal") ||
                                                                strings.Contains(p, "config") ||
                                                                strings.Contains(p, "logs") ||
                                                                strings.Contains(p, "backup") ||
                                                                strings.Contains(p, "error") ||
                                                                strings.Contains(p, "oauth") ||                                                                              
                                                                strings.Contains(p, "payment") ||
                                                                strings.Contains(p, "settings") ||
                                                                strings.Contains(p, "api/admin") ||
                                                                strings.Contains(p, "cron") ||
                                                                strings.Contains(p, "health") ||
                                                                strings.Contains(p, "legal") ||
                                                                strings.Contains(p, "invite") ||
                                                                strings.Contains(p, "internal-tools") ||
                                                                strings.Contains(p, "metrics") ||
                                                                strings.Contains(p, "webhooks") ||
                                                                strings.Contains(p, "report") ||
                                                                strings.Contains(p, "audit") ||
                                                                strings.Contains(p, "secrets") ||
                                                                strings.Contains(p, "two-factor-auth") ||
                                                                strings.Contains(p, "data-export") ||
                                                                strings.Contains(p, "vpn") ||
                                                                strings.Contains(p, "purchase-history") ||
                                                                strings.Contains(p, "upgrade") ||
                                                                strings.Contains(p, "gdpr-request") ||
                                                                strings.Contains(p, "blockchain") ||
                                                                strings.Contains(p, "compliance") ||
                                                                strings.Contains(p, "sensitive-docs") ||
                                                                strings.Contains(p, "vulnerabilities") ||
                                                                strings.Contains(p, "compliance-audit") ||
                                                                strings.Contains(p, "third-party-integrations") ||
                                                                strings.Contains(p, "escalation") ||
                                                                strings.Contains(p, "vpn-logs") ||
                                                                strings.Contains(p, "legal-dispute") ||
                                                                strings.Contains(p, "gdpr-compliance-report") ||
                                                                strings.Contains(p, "security-playbook") ||
                                                                strings.Contains(p, "emergency-shutdown") ||
                                                                strings.Contains(p, "data-import") ||
                                                                strings.Contains(p, "privileged-operations") ||
                                                                strings.Contains(p, "incident-response") ||
                                                                strings.Contains(p, "encryption-keys") ||
                                                                strings.Contains(p, "auth-logs") ||
                                                                strings.Contains(p, "compliance-standards") ||
                                                                strings.Contains(p, "user-activity") ||
                                                                strings.Contains(p, "data-erasure") ||
                                                                strings.Contains(p, "security-policies") ||
                                                                strings.Contains(p, "business-continuity") ||
                                                                strings.Contains(p, "incident-reporting") ||
                                                                strings.Contains(p, "geo-location") ||
                                                                strings.Contains(p, "compliance-framework") ||
                                                                strings.Contains(p, "biometric-data") ||
                                                                strings.Contains(p, "single-sign-on") ||
                                                                strings.Contains(p, "remote-access") ||
                                                                strings.Contains(p, "data-archiving") ||
                                                                strings.Contains(p, "compliance-auditors") ||
                                                                strings.Contains(p, "incident-resolution") ||
                                                                strings.Contains(p, "multi-factor-auth-setup") ||
                                                                strings.Contains(p, "privacy-settings") ||
                                                                strings.Contains(p, "data-encryption") ||
                                                                strings.Contains(p, "security-training") ||
                                                                strings.Contains(p, "compliance-checklist") ||
                                                                strings.Contains(p, "application-architecture") ||
                                                                strings.Contains(p, "threat-intelligence") ||
                                                                strings.Contains(p, "external-vulnerability-scans") ||
                                                                strings.Contains(p, "compliance-updates") ||
                                                                strings.Contains(p, "authentication-config") ||
                                                                strings.Contains(p, "session-management")
				
				},

		// non-standard port
		func(u *url.URL) bool {
			return (u.Port() != "80" && u.Port() != "443" && u.Port() != "")
		},
	}

	seen := make(map[string]bool)

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {

		u, err := url.Parse(sc.Text())
		if err != nil {
			//fmt.Fprintf(os.Stderr, "failed to parse url %s [%s]\n", sc.Text(), err)
			continue
		}

		if isBoringStaticFile(u) {
			continue
		}

		
		pp := make([]string, 0)
		for p, _ := range u.Query() {
			pp = append(pp, p)
		}
		sort.Strings(pp)

		key := fmt.Sprintf("%s%s?%s", u.Hostname(), u.EscapedPath(), strings.Join(pp, "&"))

		// Only output each host + path + params combination once
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = true

		interesting := 0

		for _, check := range checks {
			if check(u) {
				interesting++
			}
		}

		if interesting > 0 {
			fmt.Println(sc.Text())
		}

	}

}


func qsCheck(k, v string) bool {
	k = strings.ToLower(k)
	v = strings.ToLower(v)

	// the super-common utm_referrer etc
	// are rarely interesting
	if strings.HasPrefix(k, "utm_") {
		return false
	}

	// value checks
	return strings.HasPrefix(v, "http") ||
		strings.Contains(v, "{") ||
		strings.Contains(v, "[") ||
		strings.Contains(v, "/") ||
		strings.Contains(v, "\\") ||
		strings.Contains(v, "<") ||
		strings.Contains(v, "(") ||
		// shoutout to liveoverflow ;)
		strings.Contains(v, "eyj") ||

		// key checks
		strings.Contains(k, "redirect") ||
		strings.Contains(k, "debug") ||
		strings.Contains(k, "password") ||
		strings.Contains(k, "passwd") ||
		strings.Contains(k, "file") ||
		strings.Contains(k, "fn") ||
		strings.Contains(k, "template") ||
		strings.Contains(k, "include") ||
		strings.Contains(k, "require") ||
		strings.Contains(k, "url") ||
		strings.Contains(k, "uri") ||
		strings.Contains(k, "src") ||
		strings.Contains(k, "href") ||
		strings.Contains(k, "func") ||
		strings.Contains(k, "callback") ||
		strings.Contains(k, "user") ||
		strings.Contains(k, "process") ||
		strings.Contains(k, "update") ||
		strings.Contains(k, "role") ||
		strings.Contains(k, "report") ||
		strings.Contains(k, "table") ||
		strings.Contains(k, "board") ||
		strings.Contains(k, "path") ||
		strings.Contains(k, "folde") ||
		strings.Contains(k, "dir") ||
		strings.Contains(k, "data") ||
		strings.Contains(k, "daemon") ||
		strings.Contains(k, "download") ||
		strings.Contains(k, "prefix") ||
		strings.Contains(k, "account") ||
		strings.Contains(k, "order") ||
		strings.Contains(k, "key") ||
		strings.Contains(k, "group") ||
		strings.Contains(k, "profile") ||
		strings.Contains(k, "edit") ||
		strings.Contains(k, "email") ||
		strings.Contains(k, "keywords") ||
		strings.Contains(k, "api_key") ||
		strings.Contains(k, "ip") ||
		strings.Contains(k, "cmd") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "dest") ||
		strings.Contains(k, "window") ||
		strings.Contains(k, "host") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "authorization") ||
		strings.Contains(k, "adminer") ||
		strings.Contains(k, "wpadmin") ||
		strings.Contains(k, "dashboard") ||
		strings.Contains(k, "access") ||
		strings.Contains(k, "privilege") ||
		strings.Contains(k, "policy") ||
		strings.Contains(k, "log") ||
		strings.Contains(k, "command") ||
		strings.Contains(k, "ping") ||
		strings.Contains(k, "code") ||
		strings.Contains(k, "locate") ||
		strings.Contains(k, "column") ||
		strings.Contains(k, "number") ||
		strings.Contains(k, "filter") ||
		strings.Contains(k, "internal") ||
		strings.Contains(k, "query") ||
		strings.Contains(k, "port")
}

func isBoringStaticFile(u *url.URL) bool {
	exts := []string{
		// OK, so JS could be interesting, but 99% of the time it's boring.
		".js",
                                ".html",
		".htm",
		".svg",
		".eot",
		".ttf",
		".woff",
		".woff2",
		".png",
		".jpg",
		".jpeg",
		".gif",
		".ico",
	}

	p := strings.ToLower(u.EscapedPath())
	for _, e := range exts {
		if strings.HasSuffix(p, e) {
			return true
		}
	}

	return false
}

package config

// Preset is an editable starter template for a policy.
type Preset struct {
	Key     string   `json:"key"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	ASNs    []int    `json:"asns"`
	Notes   string   `json:"notes"`
}

// Presets are starting points only; they are copied into a policy and the
// user owns them from then on. Streaming services change their CDNs, so use
// the diagnostics "test domain" tool and the live ipset view to refine them.
var Presets = []Preset{
	{
		Key:  "netflix",
		Name: "Netflix",
		Domains: []string{
			"netflix.com", "netflix.net", "nflximg.com", "nflximg.net",
			"nflxvideo.net", "nflxso.net", "nflxext.com", "nflxsearch.net",
			"netflixdnstest0.com", "netflixdnstest1.com", "netflixdnstest2.com",
			"netflixdnstest3.com", "netflixdnstest4.com", "netflixdnstest5.com",
			"netflixdnstest6.com", "netflixdnstest7.com", "netflixdnstest8.com",
			"netflixdnstest9.com", "netflixdnstest10.com",
		},
		ASNs:  []int{2906, 40027},
		Notes: "Open Connect caches inside your ISP are reached via nflxvideo.net, which the dnsmasq ipset catches. ASN 2906/40027 covers Netflix-owned ranges.",
	},
	{
		Key:  "disneyplus",
		Name: "Disney+",
		Domains: []string{
			"disneyplus.com", "disney-plus.net", "disneystreaming.com",
			"dssott.com", "bamgrid.com", "dssedge.com", "starott.com",
			"registerdisney.go.com", "disneyplus.bn5x.net", "disney-portal.my.onetrust.com",
		},
		Notes: "Disney+ uses third-party CDNs (Akamai, CloudFront, Fastly); domain matching is what makes it work, so keep DNS hijack and DoH blocking on.",
	},
}

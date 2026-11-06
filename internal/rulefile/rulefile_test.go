package rulefile

import (
	"strings"
	"testing"
)

const sample = `# snake rules v1
@name Netflix
@description Netflix  streaming
@source https://example.com/netflix.rules

# core
netflix.com
NFLXVIDEO.net.
**.nflxvideo.net
/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/
~nflxso
!=ads.netflix.com
netflix.com
asn:AS2906
ASN: 40027
asn:2906
cidr:23.246.0.0/18
ip:198.38.96.1 # single host
`

func TestParseAndFormat(t *testing.T) {
	r := Parse(sample, false)
	if len(r.Errors) != 0 {
		t.Fatalf("errors: %+v", r.Errors)
	}
	f := r.File
	if f.Name != "Netflix" || f.Description != "Netflix  streaming" || f.Source != "https://example.com/netflix.rules" {
		t.Fatalf("meta: %+v", f)
	}
	want := []string{"# core", "netflix.com", "nflxvideo.net", "**.nflxvideo.net", `/^ipv4-c\d+-.*\.oca\.nflxvideo\.net$/`, "~nflxso", "!=ads.netflix.com"}
	if strings.Join(f.Domains, "\n") != strings.Join(want, "\n") {
		t.Fatalf("domains:\n%s", strings.Join(f.Domains, "\n"))
	}
	if len(f.ASNs) != 2 || f.ASNs[0] != 2906 || f.ASNs[1] != 40027 {
		t.Fatalf("asns %v", f.ASNs)
	}
	if len(f.CIDRs) != 2 || f.CIDRs[1] != "198.38.96.1" {
		t.Fatalf("cidrs %v", f.CIDRs)
	}
	// Round trip: Format then Parse yields the same file.
	out := Format(f)
	if !strings.HasPrefix(out, Header+"\n@name Netflix\n@description Netflix streaming\n") {
		t.Fatalf("format:\n%s", out)
	}
	r2 := Parse(out, false)
	if Format(r2.File) != out || len(r2.Errors) != 0 {
		t.Fatalf("round trip differs:\n%s\n---\n%s", out, Format(r2.File))
	}
}

func TestErrorsHaveLineNumbers(t *testing.T) {
	r := Parse("netflix.com\n\nbad domain\nasn:xyz\ncidr:300.1.1.1\n/bad(/\n@colour blue\n", false)
	lines := []int{}
	for _, e := range r.Errors {
		lines = append(lines, e.Line)
	}
	if len(lines) != 4 || lines[0] != 3 || lines[1] != 4 || lines[2] != 5 || lines[3] != 6 {
		t.Fatalf("errors: %+v", r.Errors)
	}
	if len(r.Warnings) != 1 || r.Warnings[0].Line != 7 {
		t.Fatalf("warnings: %+v", r.Warnings)
	}
}

func TestConvert(t *testing.T) {
	in := "! Title: some list\n||disneyplus.com^\n||bamgrid.com^$third-party\n0.0.0.0 ads.example.com tracker.example.com # x\n127.0.0.1 localhost\nserver=/dssott.com/starott.com/1.1.1.1\nipset=/hulu.com/SOMESET\n!=keep.example.com\n"
	r := Parse(in, true)
	if len(r.Errors) != 0 {
		t.Fatalf("errors: %+v", r.Errors)
	}
	want := "disneyplus.com bamgrid.com =ads.example.com =tracker.example.com dssott.com starott.com hulu.com !=keep.example.com"
	if got := strings.Join(r.File.Domains, " "); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if r.Converted != 7 {
		t.Fatalf("converted = %d", r.Converted)
	}
	// Without convert, foreign lines are errors.
	if r := Parse("||disneyplus.com^\n", false); len(r.Errors) != 1 {
		t.Fatalf("expected error without convert: %+v", r)
	}
}

package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseBlocklist(t *testing.T) {
	var b strings.Builder
	b.WriteString("# header\n\nnot-an-ip\n2001:db8::1\n")
	for i := 0; i < minValidIPs; i++ {
		fmt.Fprintf(&b, "8.8.%d.%d\n", i/256, i%256)
	}
	list, err := parseBlocklist(strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != minValidIPs {
		t.Fatalf("got %d IPs, want %d", len(list), minValidIPs)
	}
}

func TestParseBlocklistRejectsBadBodies(t *testing.T) {
	for name, body := range map[string]string{
		"empty":    "",
		"html":     "<html>404: Not Found</html>\n",
		"too few":  "1.2.3.4\n5.6.7.8\n",
		"comments": "# only\n# comments\n",
	} {
		if _, err := parseBlocklist(strings.NewReader(body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

package gateway

import (
	"bytes"
	"testing"

	"guestgate/internal/upstream"
)

func TestScopedConfigRemoval(t *testing.T) {
	for _, original := range []string{"existing\r\n", "existing\n", "existing"} {
		block := "\r\n" + begin + "\r\nhost test {}\r\n" + end + "\r\n"
		after := "# unrelated change\n"
		got, e := unmanaged([]byte(original + block + after))
		if e != nil || !bytes.Equal(got, []byte(original+after)) {
			t.Fatalf("restore %q: %q %v", original, got, e)
		}
	}
	if _, e := unmanaged([]byte("\r\n" + begin + "\n")); e == nil {
		t.Fatal("incomplete entry accepted")
	}
}
func TestProxyValidation(t *testing.T) {
	for _, v := range []string{"direct://127.0.0.1:80", "socks5s://proxy:80", "socks5://host:0", "socks5://host:70000"} {
		if _, e := upstream.Parse(v); e == nil {
			t.Fatalf("accepted %s", v)
		}
	}
	client, e := upstream.Parse("socks5://a:p%40ss@[::1]:1080")
	if e != nil || client.Server != "[::1]:1080" {
		t.Fatal("credential or IPv6 parsing failed")
	}
}

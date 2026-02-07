package inventory

import "testing"

func TestParseNextLink(t *testing.T) {
	link := "<https://example.okta.com/api/v1/users?after=123>; rel=\"next\", <https://example.okta.com/api/v1/users?after=0>; rel=\"self\""
	next := parseNextLink(link)
	if next == "" || next != "https://example.okta.com/api/v1/users?after=123" {
		t.Fatalf("unexpected next link: %s", next)
	}
}

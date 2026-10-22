package version

import "testing"

func TestStringPrefersTheLinkedValue(t *testing.T) {
	defer func(old string) { current = old }(current)
	current = "1.2.3"
	if got := String(); got != "1.2.3" {
		t.Fatalf("String() = %q", got)
	}
	current = ""
	if got := String(); got == "" {
		t.Fatal("String() is empty without a linked value")
	}
}

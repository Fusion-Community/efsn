package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestOperatorRequiresReviewedDigest(t *testing.T) {
	for _, value := range []string{"", "0x01", strings.Repeat("0", 64), strings.Repeat("g", 64)} {
		if _, err := parseDigest(value); err == nil {
			t.Fatalf("invalid digest accepted: %q", value)
		}
	}
	if _, err := parseDigest(strings.Repeat("1", 64)); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"sign"}, {"init-journal"}, {"export"}, {"prepare"}, {"unknown"}, {"sign", "-password", "not-a-secret"}} {
		if err := runCommand(args); err == nil {
			t.Fatalf("incomplete or unsupported command accepted: %v", args)
		}
	}
}

func TestPasswordLinePreservesWhitespaceAndBounds(t *testing.T) {
	for _, input := range []string{" public test \r\n", " public test \n", " public test "} {
		password, err := readPasswordLine(strings.NewReader(input))
		if err != nil || !bytes.Equal(password, []byte(" public test ")) {
			t.Fatalf("password changed: %v", err)
		}
	}
	if _, err := readPasswordLine(strings.NewReader(strings.Repeat("x", 4097))); err == nil {
		t.Fatal("oversized password accepted")
	}
}

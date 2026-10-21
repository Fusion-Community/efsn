package logjson

import "testing"

func TestLegacyEscaping(t *testing.T) {
	data, err := Marshal(map[string]interface{}{"Name": "\b\f\n<&>\u2028\xff"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Name":"\u0008\u000c\n\u003c\u0026\u003e\u2028\ufffd"}`
	if string(data) != want {
		t.Fatalf("have %s, want %s", data, want)
	}
}

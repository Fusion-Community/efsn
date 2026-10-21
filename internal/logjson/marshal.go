package logjson

import "github.com/FusionFoundation/efsn/v5/internal/logjson/internal/json"

func Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

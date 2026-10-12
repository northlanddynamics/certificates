package agent_test

import (
	"encoding/json"
	"testing"
)

func decodeJSON(t *testing.T, data []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatal(err)
	}
}

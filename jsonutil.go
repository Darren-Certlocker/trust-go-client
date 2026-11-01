package trustclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Time is a Trust timestamp. Gateway JSON uses UTC, commonly
// 2006-01-02T15:04:05.000Z. Missing values stay nil on pointer fields.
type Time struct {
	time.Time
}

// UnmarshalJSON parses a Trust timestamp.
func (t *Time) UnmarshalJSON(b []byte) error {
	if t == nil {
		return fmt.Errorf("nil Time")
	}
	raw := bytes.TrimSpace(b)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || bytes.Equal(raw, []byte(`""`)) {
		t.Time = time.Time{}
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	parsed, err := parseTrustTime(s)
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

// MarshalJSON writes a UTC timestamp in the Trust wire format.
func (t Time) MarshalJSON() ([]byte, error) {
	if t.Time.IsZero() {
		return []byte("null"), nil
	}
	return json.Marshal(t.Time.UTC().Format("2006-01-02T15:04:05.000Z"))
}

func parseTrustTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return ts, nil
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05.000",
		"2006-01-02T15:04:05",
	} {
		if ts, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse time %q", s)
}

// StringList decodes a JSON string or an array of strings.
type StringList []string

// UnmarshalJSON accepts a JSON string or an array of strings.
func (s *StringList) UnmarshalJSON(b []byte) error {
	items, err := flexStrings(b)
	if err != nil {
		return err
	}
	*s = items
	return nil
}

func flexStrings(b []byte) ([]string, error) {
	raw := bytes.TrimSpace(b)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	if raw[0] == '"' {
		var one string
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, err
		}
		if one == "" {
			return nil, nil
		}
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, err
	}
	return many, nil
}

func decodeJSON[T any](body string) (*T, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var v T
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return nil, &Error{Message: "invalid JSON response", Cause: err}
	}
	return &v, nil
}

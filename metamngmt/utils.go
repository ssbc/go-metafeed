package metamngmt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Base64String encodes a slice of bytes as a base64 string in unicode.
// This is the default in go but we just want to be double sure this sticks and doesnt change under our feet in the future.
type Base64String []byte

// MarshalJSON turns a go value into a json string.
func (s Base64String) MarshalJSON() ([]byte, error) {
	str := base64.StdEncoding.EncodeToString(s)
	return json.Marshal(str)
}

// UnmarshalJSON turns json data into a go value.
func (s *Base64String) UnmarshalJSON(data []byte) error {
	var strData string
	err := json.Unmarshal(data, &strData)
	if err != nil {
		return fmt.Errorf("base64string: json decode of string failed: %w", err)
	}

	rawData, err := base64.StdEncoding.DecodeString(strData)
	if err != nil {
		return fmt.Errorf("base64string: decoding hex to raw bytes failed: %w", err)
	}

	*s = rawData
	return nil
}

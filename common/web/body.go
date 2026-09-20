package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// DecodeJSONBody decodes exactly one JSON value while bounding memory use.
// HTTP handlers should use this for every request body that is not streamed.
func DecodeJSONBody(_ http.ResponseWriter, r *http.Request, dst interface{}, maxBytes int64) error {
	if r == nil || r.Body == nil {
		return fmt.Errorf("request body required")
	}
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("request body exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request must contain one JSON value")
	}
	return nil
}

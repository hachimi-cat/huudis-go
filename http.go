package huudis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// RequestAuth lets callers override the client-level bearer token for a
// single resource call. Empty AuthToken keeps the client default
// (currently: none — admin operations always pass an explicit token).
type RequestAuth struct {
	AuthToken string
}

// requestOptions is the internal merged shape passed to do().
type requestOptions struct {
	authToken string
	query     url.Values
	body      any
}

// envelope mirrors the Forjio data/error/meta API envelope. We unmarshal
// into this first and then decode .Data into the caller's target type.
type envelope struct {
	Data  json.RawMessage `json:"data"`
	Error *envelopeError  `json:"error"`
	Meta  *envelopeMeta   `json:"meta"`
}

type envelopeError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

type envelopeMeta struct {
	RequestID  string `json:"requestId,omitempty"`
	Timestamp  string `json:"timestamp,omitempty"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// doRequest is the workhorse: builds the request, attaches the bearer,
// parses the envelope, and decodes the data slot into `out` (pointer).
// `out == nil` means "ignore body" (used by void DELETEs).
func (c *Client) doRequest(
	ctx context.Context,
	method, path string,
	opts requestOptions,
	out any,
) error {
	u := c.APIBase + path
	if len(opts.query) > 0 {
		u += "?" + opts.query.Encode()
	}

	var bodyReader io.Reader
	if opts.body != nil {
		raw, err := json.Marshal(opts.body)
		if err != nil {
			return newErr("SERIALIZE_FAILED", err.Error())
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return newErr("REQUEST_BUILD_FAILED", err.Error())
	}
	req.Header.Set("Accept", "application/json")
	if opts.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if opts.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+opts.authToken)
	}

	res, err := c.HTTP.Do(req)
	if err != nil {
		return newErr("HTTP_REQUEST_FAILED", err.Error())
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)

	// 204 / empty body: success, nothing to decode.
	if len(bytes.TrimSpace(raw)) == 0 {
		if res.StatusCode >= 400 {
			return newErr("HTTP_ERROR", fmt.Sprintf("HTTP %d", res.StatusCode))
		}
		return nil
	}

	// Try the Forjio envelope first.
	var env envelope
	envelopeOK := false
	if err := json.Unmarshal(raw, &env); err == nil {
		// Heuristic: presence of all three top-level keys means it IS the envelope.
		// We only need a quick map-decode for that, but a successful Unmarshal of the
		// struct is good enough — Data/Meta will be zero-value if missing.
		var probe map[string]json.RawMessage
		_ = json.Unmarshal(raw, &probe)
		_, hasData := probe["data"]
		_, hasError := probe["error"]
		_, hasMeta := probe["meta"]
		envelopeOK = hasData && hasError && hasMeta
	}

	if envelopeOK {
		if env.Error != nil {
			code := env.Error.Code
			if code == "" {
				code = "UNKNOWN"
			}
			return newErr(code, env.Error.Message)
		}
		if out == nil {
			return nil
		}
		// `data` can legitimately be `null` — leave out untouched.
		if len(env.Data) == 0 || bytes.Equal(env.Data, []byte("null")) {
			return nil
		}
		if err := json.Unmarshal(env.Data, out); err != nil {
			return newErr("DECODE_FAILED", err.Error())
		}
		return nil
	}

	// Non-envelope response. If HTTP failed, surface that.
	if res.StatusCode >= 400 {
		// Try to read {error:{code,message}} or {error,error_description}.
		var alt struct {
			Error            any    `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(raw, &alt)
		code, msg := "HTTP_ERROR", fmt.Sprintf("HTTP %d", res.StatusCode)
		switch e := alt.Error.(type) {
		case map[string]any:
			if v, ok := e["code"].(string); ok && v != "" {
				code = v
			}
			if v, ok := e["message"].(string); ok && v != "" {
				msg = v
			}
		case string:
			if alt.ErrorDescription != "" {
				msg = alt.ErrorDescription
			} else if e != "" {
				msg = e
			}
		}
		return newErr(code, msg)
	}

	// 2xx with no envelope (rare — direct JSON). Decode straight into out.
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return newErr("DECODE_FAILED", err.Error())
	}
	return nil
}

// buildQuery builds a url.Values from a flat map. Nil/empty values are
// dropped so callers can pass zero-value structs without polluting the
// query string. Booleans go in as "true"/"false". Ints/int64s use
// strconv.
func buildQuery(kv map[string]any) url.Values {
	q := url.Values{}
	for k, v := range kv {
		switch x := v.(type) {
		case nil:
			continue
		case string:
			if x == "" {
				continue
			}
			q.Set(k, x)
		case bool:
			q.Set(k, strconv.FormatBool(x))
		case int:
			if x == 0 {
				continue
			}
			q.Set(k, strconv.Itoa(x))
		case int64:
			if x == 0 {
				continue
			}
			q.Set(k, strconv.FormatInt(x, 10))
		case float64:
			if x == 0 {
				continue
			}
			q.Set(k, strconv.FormatFloat(x, 'f', -1, 64))
		case *string:
			if x == nil || *x == "" {
				continue
			}
			q.Set(k, *x)
		case *bool:
			if x == nil {
				continue
			}
			q.Set(k, strconv.FormatBool(*x))
		case *int:
			if x == nil || *x == 0 {
				continue
			}
			q.Set(k, strconv.Itoa(*x))
		default:
			s := fmt.Sprintf("%v", x)
			if s == "" {
				continue
			}
			q.Set(k, s)
		}
	}
	return q
}

// helper: keep "/api/v1/..." paths from accidentally double-slashing.
func joinPath(parts ...string) string {
	out := strings.Join(parts, "/")
	for strings.Contains(out, "//") {
		out = strings.ReplaceAll(out, "//", "/")
	}
	return out
}

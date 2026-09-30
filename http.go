package huudis

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// RequestAuth lets callers override the client-level credential with a bearer
// token for a single resource call. Empty AuthToken keeps the client default:
// ClientOptions.Token, else the access key (see ClientOptions).
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

func isAppRoute(path string) bool {
	return path == "/api/v1/app" || strings.HasPrefix(path, "/api/v1/app/")
}

// apigenRequest is the call behind Client.API (api_generated.go): the same
// credentials and envelope handling as every resource method.
func (c *Client) apigenRequest(ctx context.Context, method, path string, query url.Values, body map[string]any) (json.RawMessage, error) {
	return c.Do(ctx, method, path, query, body)
}

// Do sends one request to any API path with the credential its route takes and
// returns the envelope's data as JSON. body (nil for none) is sent as JSON.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body any) (json.RawMessage, error) {
	opts := requestOptions{query: query}
	if m, ok := body.(map[string]any); !ok || m != nil {
		opts.body = body
	}
	var out json.RawMessage
	if err := c.doRequest(ctx, strings.ToUpper(method), path, opts, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// doRequest is the workhorse: builds the request, attaches the credential the
// route takes, parses the envelope, and decodes the data slot into `out`
// (pointer). `out == nil` means "ignore body" (used by void DELETEs).
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

	var sent []byte
	if opts.body != nil {
		b, err := json.Marshal(opts.body)
		if err != nil {
			return newErr("SERIALIZE_FAILED", err.Error())
		}
		sent = b
	}

	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(sent))
	if err != nil {
		return newErr("REQUEST_BUILD_FAILED", err.Error())
	}
	if sent == nil {
		req.Body = http.NoBody
		req.ContentLength = 0
	}
	req.Header.Set("Accept", "application/json")
	if opts.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.workspaceID != "" {
		req.Header.Set("X-Huudis-Workspace-Id", c.workspaceID)
	}
	switch {
	case isAppRoute(path):
		// The app-to-app surface takes the OIDC client's own credentials only.
		if c.ClientID == "" || c.ClientSecret == "" {
			return newErr("MISSING_CLIENT_CREDENTIALS",
				"/api/v1/app/* authenticates as your OIDC app: set ClientOptions.ClientID + ClientSecret (or HUUDIS_CLIENT_ID + HUUDIS_CLIENT_SECRET)")
		}
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.ClientID+":"+c.ClientSecret)))
	case opts.authToken != "":
		req.Header.Set("Authorization", "Bearer "+opts.authToken)
	case c.token != "":
		req.Header.Set("Authorization", "Bearer "+c.token)
	case c.accessKeyID != "" && c.secretAccessKey != "":
		// Sign exactly the target the request line carries, and the bytes sent.
		authorization, date := SignRequest(c.accessKeyID, c.secretAccessKey, method, req.URL.RequestURI(), sent, c.now())
		req.Header.Set("Authorization", authorization)
		req.Header.Set("X-Huudis-Date", date)
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
			e := newErr("HTTP_ERROR", fmt.Sprintf("HTTP %d", res.StatusCode))
			e.Status = res.StatusCode
			return e
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
			e := newErr(code, env.Error.Message)
			e.Status = res.StatusCode
			if env.Meta != nil {
				e.RequestID = env.Meta.RequestID
			}
			return e
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
		e := newErr(code, msg)
		e.Status = res.StatusCode
		return e
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

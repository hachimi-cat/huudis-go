package huudis

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// VerifyWebhookSignatureOptions tunes the webhook verifier. Pass a pointer
// to a zero-value struct to use the defaults.
type VerifyWebhookSignatureOptions struct {
	// ToleranceSeconds rejects signatures with a timestamp older than this
	// many seconds. Zero or negative means "use the default" (300).
	ToleranceSeconds int64
	// Now is the clock used for the freshness check. Nil means time.Now.
	// Useful in tests.
	Now func() time.Time
}

// VerifyWebhookSignature returns true iff the X-Huudis-Signature header
// over the given raw request body validates against the provided secret
// within the tolerance window.
//
// The signature header looks like "t=<unix>,v1=<hex>", where <hex> is
// HMAC-SHA256(secret, fmt.Sprintf("%d.%s", unix, rawBody)). Mount your
// webhook handler such that you can see the raw bytes — if you let a
// framework parse JSON first and re-stringify, whitespace drift will break
// the signature.
//
// net/http example:
//
//	func huudisWebhook(w http.ResponseWriter, r *http.Request) {
//	    body, err := io.ReadAll(r.Body)
//	    if err != nil { http.Error(w, "bad body", 400); return }
//	    sig := r.Header.Get("X-Huudis-Signature")
//	    if !huudis.VerifyWebhookSignature(body, sig, os.Getenv("HUUDIS_WEBHOOK_SECRET"), nil) {
//	        http.Error(w, "bad signature", 400); return
//	    }
//	    // unmarshal body, handle event, reply 204.
//	}
func VerifyWebhookSignature(
	rawBody []byte,
	signatureHeader string,
	secret string,
	options *VerifyWebhookSignatureOptions,
) bool {
	if signatureHeader == "" || secret == "" {
		return false
	}

	tolerance := int64(300)
	nowFn := time.Now
	if options != nil {
		if options.ToleranceSeconds > 0 {
			tolerance = options.ToleranceSeconds
		}
		if options.Now != nil {
			nowFn = options.Now
		}
	}

	timestamp, expectedV1, ok := parseHuudisSignature(signatureHeader)
	if !ok {
		return false
	}
	nowTs := nowFn().Unix()
	if diff := nowTs - timestamp; diff > tolerance || diff < -tolerance {
		return false
	}

	payload := strconv.FormatInt(timestamp, 10) + "." + string(rawBody)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	computed := hex.EncodeToString(mac.Sum(nil))

	expected, err := hex.DecodeString(expectedV1)
	if err != nil {
		return false
	}
	actual, err := hex.DecodeString(computed)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, actual)
}

func parseHuudisSignature(header string) (timestamp int64, v1 string, ok bool) {
	parts := strings.Split(header, ",")
	var tSeen, v1Seen bool
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		k, v, found := strings.Cut(p, "=")
		if !found {
			continue
		}
		switch k {
		case "t":
			if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
				timestamp = ts
				tSeen = true
			}
		case "v1":
			v1 = v
			v1Seen = true
		}
	}
	return timestamp, v1, tSeen && v1Seen
}

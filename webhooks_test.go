package huudis

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// TestVerifyWebhookSignature_RoundTrip signs a payload the exact way the
// backend does (see backend/src/services/webhooks.ts#signBody) and verifies
// the SDK accepts it. If this breaks, the SDK and the backend have drifted
// and every real webhook will start 400ing.
func TestVerifyWebhookSignature_RoundTrip(t *testing.T) {
	secret := "whsec_test_secret_1234567890"
	body := []byte(`{"id":"evt_x","type":"huudis.user.created.v1","data":{"userId":"usr_1"}}`)
	timestamp := int64(1_750_000_000)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.", timestamp) + string(body)))
	sigHeader := fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(mac.Sum(nil)))

	fixedClock := func() time.Time { return time.Unix(timestamp+10, 0) }

	if !VerifyWebhookSignature(body, sigHeader, secret, &VerifyWebhookSignatureOptions{Now: fixedClock}) {
		t.Fatal("valid signature rejected")
	}
}

func TestVerifyWebhookSignature_Tampered(t *testing.T) {
	secret := "whsec_x"
	timestamp := int64(1_750_000_000)
	body := []byte(`{"hello":"world"}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.", timestamp) + string(body)))
	good := hex.EncodeToString(mac.Sum(nil))

	tampered := []byte(`{"hello":"mars"}`) // same length, different content
	sigHeader := fmt.Sprintf("t=%d,v1=%s", timestamp, good)

	fixedClock := func() time.Time { return time.Unix(timestamp, 0) }

	if VerifyWebhookSignature(tampered, sigHeader, secret, &VerifyWebhookSignatureOptions{Now: fixedClock}) {
		t.Fatal("tampered body verified true")
	}
}

func TestVerifyWebhookSignature_Expired(t *testing.T) {
	secret := "whsec_x"
	timestamp := int64(1_750_000_000)
	body := []byte(`{}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.", timestamp) + string(body)))
	sigHeader := fmt.Sprintf("t=%d,v1=%s", timestamp, hex.EncodeToString(mac.Sum(nil)))

	// 10 min after signing — outside the default 5 min tolerance.
	fixedClock := func() time.Time { return time.Unix(timestamp+600, 0) }

	if VerifyWebhookSignature(body, sigHeader, secret, &VerifyWebhookSignatureOptions{Now: fixedClock}) {
		t.Fatal("stale signature accepted")
	}
}

func TestVerifyWebhookSignature_MalformedHeader(t *testing.T) {
	if VerifyWebhookSignature([]byte("x"), "not-a-valid-header", "s", nil) {
		t.Fatal("bogus header accepted")
	}
	if VerifyWebhookSignature([]byte("x"), "", "s", nil) {
		t.Fatal("empty header accepted")
	}
	if VerifyWebhookSignature([]byte("x"), "t=abc,v1=deadbeef", "s", nil) {
		t.Fatal("non-numeric timestamp accepted")
	}
}

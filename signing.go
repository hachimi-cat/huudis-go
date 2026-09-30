package huudis

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// SignRequest signs one request with an IAM access key (Huudis-HMAC-SHA256) and
// returns the Authorization and X-Huudis-Date header values:
//
//	StringToSign = METHOD "\n" PATH-WITH-QUERY "\n" X-Huudis-Date "\n" hex(sha256(body))
//	Signature    = hex(HMAC-SHA256(secret, StringToSign))
//
// pathWithQuery is exactly the request line's target (/api/v1/iam/users?x=1) and body
// the exact bytes sent (nil for none). Huudis accepts an X-Huudis-Date within 5 minutes
// of its clock.
func SignRequest(accessKeyID, secretAccessKey, method, pathWithQuery string, body []byte, at time.Time) (authorization, date string) {
	date = at.UTC().Format("2006-01-02T15:04:05.000Z")
	bodyHash := sha256.Sum256(body)
	stringToSign := strings.ToUpper(method) + "\n" + pathWithQuery + "\n" + date + "\n" + hex.EncodeToString(bodyHash[:])
	mac := hmac.New(sha256.New, []byte(secretAccessKey))
	mac.Write([]byte(stringToSign))
	authorization = "Huudis-HMAC-SHA256 Credential=" + accessKeyID + ", Signature=" + hex.EncodeToString(mac.Sum(nil))
	return authorization, date
}

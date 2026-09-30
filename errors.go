package huudis

import "fmt"

// Error is the single error type returned by every operation in this
// package. Wraps an opaque code plus a message so callers can branch on
// well-defined error reasons without matching strings.
type Error struct {
	Code    string
	Message string
	// Status is the HTTP status of an API error (0 when no response was read).
	Status int
	// RequestID is the API envelope's meta.requestId, when there was one.
	RequestID string
}

func (e *Error) Error() string {
	return fmt.Sprintf("huudis: %s: %s", e.Code, e.Message)
}

func newErr(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

package huudis

import "fmt"

// Error is the single error type returned by every operation in this
// package. Wraps an opaque code plus a message so callers can branch on
// well-defined error reasons without matching strings.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("huudis: %s: %s", e.Code, e.Message)
}

func newErr(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

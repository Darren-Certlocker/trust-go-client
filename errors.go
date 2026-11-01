package trustclient

import "fmt"

// Error is a failure returned by Trust, or a failure while calling Trust.
// HTTPStatus is set when the failure came from an HTTP error response.
type Error struct {
	Message    string
	HTTPStatus int
	Cause      error
}

// Error returns the detail message.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "trust client error"
}

// Unwrap returns the underlying failure, if any.
func (e *Error) Unwrap() error { return e.Cause }

// HasTrustError reports whether this error carries a Trust HTTP error response.
func (e *Error) HasTrustError() bool {
	return e != nil && e.HTTPStatus != 0
}

func trustErr(message string) error {
	return &Error{Message: message}
}

func trustErrf(format string, args ...any) error {
	return &Error{Message: fmt.Sprintf(format, args...)}
}

func wrapErr(message string, cause error) error {
	if cause == nil {
		return trustErr(message)
	}
	return &Error{Message: message, Cause: cause}
}

package enroll

import (
	"errors"
	"strings"
)

// IsDeadCredential reports auth responses that mean the renewal token (or
// agent) can never succeed again without re-enrollment. Transient network and
// 429 rate-limit errors must not match.
func IsDeadCredential(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	var api *APIError
	if errors.As(err, &api) && api.Message != "" {
		msg = strings.ToLower(api.Message)
	}
	switch {
	case strings.Contains(msg, "renewal token expired"),
		strings.Contains(msg, "renewal token revoked"),
		strings.Contains(msg, "renewal token reused"),
		strings.Contains(msg, "invalid renewal token"),
		strings.Contains(msg, "agent not found or revoked"):
		return true
	default:
		return false
	}
}

// IsCertValidityMessage reports leaf/TLS time-validity errors (clock skew or
// truly expired cert). Used with ExcessiveClockSkew to pick a clock message.
func IsCertValidityMessage(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "certificate not yet valid") ||
		strings.Contains(msg, "certificate expired") ||
		strings.Contains(msg, "not valid yet") ||
		strings.Contains(msg, "has expired") ||
		strings.Contains(msg, "certificate is not currently valid")
}

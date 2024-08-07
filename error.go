package emailverifier

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// Standard Errors
	ErrTimeout           = "The connection to the mail server has timed out"
	ErrNoSuchHost        = "Mail server does not exist"
	ErrServerUnavailable = "Mail server is unavailable"
	ErrBlocked           = "Blocked by mail server"

	// RCPT Errors
	ErrTryAgainLater           = "Try again later"
	ErrFullInbox               = "Recipient out of disk space"
	ErrTooManyRCPT             = "Too many recipients"
	ErrNoRelay                 = "Not an open relay"
	ErrMailboxBusy             = "Mailbox busy"
	ErrExceededMessagingLimits = "Messaging limits have been exceeded"
	ErrNotAllowed              = "Not Allowed"
	ErrNeedMAILBeforeRCPT      = "Need MAIL before RCPT"
	ErrRCPTHasMoved            = "Recipient has moved"
)

// LookupError is an MX dns records lookup error
type LookupError struct {
	Code    int
	Message string `json:"message" xml:"message"`
	Details string `json:"details" xml:"details"`
}

// newLookupError creates a new LookupError reference and returns it
func newLookupError(code int, message, details string) *LookupError {
	return &LookupError{code, message, details}
}

func (e *LookupError) Error() string {
	return fmt.Sprintf("%s : %s", e.Message, e.Details)
}

// ParseSMTPError receives an MX Servers response message
// and generates the corresponding MX error
func ParseSMTPError(err error) *LookupError {
	errStr := err.Error()

	// Verify the length of the error before reading nil indexes
	if len(errStr) < 3 {
		return parseBasicErr(0, err)
	}

	// Strips out the status code string and converts to an integer for parsing
	status, convErr := strconv.Atoi(string([]rune(errStr)[0:3]))
	if convErr != nil {
		return parseBasicErr(status, err)
	}

	// If the status code is above 400 there was an error and we should return it
	if status > 400 {
		// Don't return an error if the error contains anything about the address
		// being undeliverable
		if insContains(errStr,
			"undeliverable",
			"does not exist",
			"may not exist",
			"user unknown",
			"user not found",
			"invalid address",
			"recipient invalid",
			"recipient rejected",
			"address rejected",
			"no mailbox") {
			return newLookupError(status, ErrServerUnavailable, errStr)
		}

		switch status {
		case 421:
			return newLookupError(status, ErrTryAgainLater, errStr)
		case 450:
			return newLookupError(status, ErrMailboxBusy, errStr)
		case 451:
			return newLookupError(status, ErrExceededMessagingLimits, errStr)
		case 452:
			if insContains(errStr,
				"full",
				"space",
				"over quota",
				"insufficient",
			) {
				return newLookupError(status, ErrFullInbox, errStr)
			}
			return newLookupError(status, ErrTooManyRCPT, errStr)
		case 503:
			return newLookupError(status, ErrNeedMAILBeforeRCPT, errStr)
		case 550: // 550 is Mailbox Unavailable - usually undeliverable, ref: https://blog.mailtrap.io/550-5-1-1-rejected-fix/
			if insContains(errStr,
				"spamhaus",
				"proofpoint",
				"cloudmark",
				"banned",
				"blacklisted",
				"blocked",
				"block list",
				"denied") {
				return newLookupError(status, ErrBlocked, errStr)
			}
			return newLookupError(status, ErrServerUnavailable, errStr)
		case 551:
			return newLookupError(status, ErrRCPTHasMoved, errStr)
		case 552:
			return newLookupError(status, ErrFullInbox, errStr)
		case 553:
			return newLookupError(status, ErrNoRelay, errStr)
		case 554:
			return newLookupError(status, ErrNotAllowed, errStr)
		default:
			return parseBasicErr(status, err)
		}
	}
	return nil
}

// parseBasicErr parses a basic MX record response and returns
// a more understandable LookupError
func parseBasicErr(status int, err error) *LookupError {
	errStr := err.Error()

	// Return a more understandable error
	switch {
	case insContains(errStr,
		"spamhaus",
		"proofpoint",
		"cloudmark",
		"banned",
		"blocked",
		"denied"):
		return newLookupError(status, ErrBlocked, errStr)
	case insContains(errStr, "timeout"):
		return newLookupError(status, ErrTimeout, errStr)
	case insContains(errStr, "no such host"):
		return newLookupError(status, ErrNoSuchHost, errStr)
	case insContains(errStr, "unavailable"):
		return newLookupError(status, ErrServerUnavailable, errStr)
	default:
		return newLookupError(status, errStr, errStr)
	}
}

// insContains returns true if any of the substrings
// are found in the passed string. This method of checking
// contains is case insensitive
func insContains(str string, subStrs ...string) bool {
	for _, subStr := range subStrs {
		if strings.Contains(strings.ToLower(str),
			strings.ToLower(subStr)) {
			return true
		}
	}
	return false
}

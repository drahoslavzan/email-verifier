package emailverifier

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// SMTP stores all information for SMTP verification lookup
type SMTP struct {
	HostExists  bool `json:"host_exists"` // is the host exists?
	FullInbox   bool `json:"full_inbox"`  // is the email account's inbox full?
	CatchAll    bool `json:"catch_all"`   // does the domain have a catch-all email address?
	Deliverable bool `json:"deliverable"` // can send an email to the email server?
	Disabled    bool `json:"disabled"`    // is the email blocked or disabled by the provider?
	UsingAPI    bool `json:"api"`
}

// CheckSMTP performs an email verification on the passed domain via SMTP
//   - the domain is the passed email domain
//   - username is used to check the deliverability of specific email address,
//
// if server is catch-all server, username will not be checked
func (v *Verifier) CheckSMTP(domain, username string) (*SMTP, error) {
	if !v.smtpCheckEnabled {
		return nil, nil
	}

	domain = DomainToASCII(domain)
	mxRecords, err := v.mxResolver.LookupMX(context.Background(), domain)
	if err != nil {
		return &SMTP{}, ParseSMTPError(err)
	}
	if len(mxRecords) == 0 {
		return &SMTP{}, newLookupError(0, ErrNoSuchHost, "No MX records found")
	}

	hosts := make([]string, len(mxRecords))
	for i, r := range mxRecords {
		hosts[i] = r.Host
	}

	return v.CheckSMTPForMX(hosts, domain, username)
}

func (v *Verifier) CheckSMTPForMX(hosts []string, domain, username string) (*SMTP, error) {
	if len(hosts) < 1 {
		return nil, nil
	}

	// Check by api when enabled and host recognized.
	for _, apiVerifier := range v.apiVerifiers {
		for _, mx := range hosts {
			if apiVerifier.isSupported(strings.ToLower(mx)) {
				res, err := apiVerifier.check(domain, username)
				if res != nil {
					res.UsingAPI = true
				}

				return res, err
			}
		}
	}

	var ret SMTP
	var err error
	email := fmt.Sprintf("%s@%s", username, domain)

	// Dial any SMTP server that will accept a connection
	client, _, err := newSMTPClient(hosts, v.proxyURI, v.dialerProvider)
	if err != nil {
		return &ret, ParseSMTPError(err)
	}

	// Defer quit the SMTP connection
	defer client.Quit()

	// Sets the HELO/EHLO hostname
	if err = client.Hello(v.helloName); err != nil {
		return &ret, ParseSMTPError(err)
	}

	// Sets the from email
	if err = client.Mail(v.fromEmail); err != nil {
		return &ret, ParseSMTPError(err)
	}

	// Host exists if we've successfully formed a connection
	ret.HostExists = true

	if v.catchAllCheckEnabled && !v.IsFreeDomain(domain) {
		ret.CatchAll = true

		// Checks the deliver ability of a randomly generated address in
		// order to verify the existence of a catch-all and etc.
		randomEmail := GenerateRandomEmail(domain)
		if err = client.Rcpt(randomEmail); err != nil {
			if e := ParseSMTPError(err); e != nil {
				switch e.Message {
				case ErrFullInbox:
					ret.FullInbox = true
				case ErrNotAllowed:
					ret.Disabled = true

				// If The client typically receives a `550 5.1.1` code as a reply to RCPT TO command,
				// In most cases, this is because the recipient address does not exist.
				case ErrServerUnavailable:
					fallthrough
				default:
					ret.CatchAll = false
				}
			}
		}

		// If the email server is a catch-all email server,
		// no need to calibrate deliverable on a specific user
		if ret.CatchAll {
			return &ret, nil
		}
	}

	// If no username provided,
	// no need to calibrate deliverable on a specific user
	if username == "" {
		return &ret, nil
	}

	if err = client.Rcpt(email); err != nil {
		err = ParseSMTPError(err)
	} else {
		ret.Deliverable = true
	}

	return &ret, err
}

// newSMTPClient generates a new available SMTP client
func newSMTPClient(hosts []string, proxyURI string, dp DialerProvider) (*smtp.Client, string, error) {
	var errs []error
	for _, h := range hosts {
		addr := h + smtpPort

		c, err := dialSMTP(addr, proxyURI, dp)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		return c, h, nil
	}

	if len(errs) > 0 {
		return nil, "", errs[0]
	}

	return nil, "", errors.New("Unexpected response dialing SMTP server")
}

// dialSMTP is a timeout wrapper for smtp.Dial. It attempts to dial an
// SMTP server (socks5 proxy supported) and fails with a timeout if timeout is reached while
// attempting to establish a new connection
func dialSMTP(addr, proxyURI string, dp DialerProvider) (*smtp.Client, error) {
	// Channel holding the new smtp.Client or error
	ch := make(chan interface{}, 1)

	dial := func() (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
	if dp != nil {
		dial = dp.MakeDial("tcp", addr)
	} else if len(proxyURI) > 0 {
		dial = func() (net.Conn, error) {
			return establishProxyConnection(addr, proxyURI)
		}
	}

	// Dial the new smtp connection
	go func() {
		var conn net.Conn
		var err error

		conn, err = dial()
		if err != nil {
			ch <- err
			return
		}

		host, _, _ := net.SplitHostPort(addr)
		client, err := smtp.NewClient(conn, host)
		if err != nil {
			ch <- err
			return
		}
		ch <- client
	}()

	// Retrieve the smtp client from our client channel or timeout
	select {
	case res := <-ch:
		switch r := res.(type) {
		case *smtp.Client:
			return r, nil
		case error:
			return nil, r
		default:
			return nil, errors.New("Unexpected response dialing SMTP server")
		}
	case <-time.After(smtpTimeout):
		return nil, errors.New("Timeout connecting to mail-exchanger")
	}
}

// GenerateRandomEmail generates a random email address using the domain passed. Used
// primarily for checking the existence of a catch-all address
func GenerateRandomEmail(domain string) string {
	r := make([]byte, 32)
	for i := 0; i < 32; i++ {
		r[i] = alphanumeric[rand.Intn(len(alphanumeric))]
	}
	return fmt.Sprintf("%s@%s", string(r), domain)

}

// establishProxyConnection connects to the address on the named network address
// via proxy protocol
func establishProxyConnection(addr, proxyURI string) (net.Conn, error) {
	u, err := url.Parse(proxyURI)
	if err != nil {
		return nil, err
	}
	dialer, err := proxy.FromURL(u, nil)
	if err != nil {
		return nil, err
	}
	return dialer.Dial("tcp", addr)
}

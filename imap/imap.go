package imap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/mail"
)

type Definition struct {
	// IP or hostname of the host to send the mail to
	Host string `json:"host" optiontype:"required"`
	// TCP port number to connect to
	Port uint16 `json:"port" default:"143"`
	// User that is sending the mail
	Username string `json:"username" optiontype:"required"`
	// The users password
	Password string `json:"password"`
	//
	Inbox string `json:"inbox" optiontype:"required"`
	// If the connection should be encrypted
	Encrypted bool `json:"encrypted" default:"false"`
	// Whether to verify the server's TLS certificate
	SkipVerifyCert bool `json:"skipVerifyCert" default:"false"`
	// Match against the mail count
	// If set to 0 will skip the check
	MatchMailCount uint32 `json:"matchMailCount" default:"0"`
	// Mail id to compare againsts. Defaults to being turned off
	MailID uint16 `json:"mailID" default:"0"`
	// Whether to match the mails subject against a regex
	MatchSubject bool `json:"matchSubject" default:"false"`
	// regex to match againsts the subject
	SubjectRegex string `json:"subjectRegex" default:".*"`
	// Whether to match the mails body against a regex
	MatchBody bool `json:"matchBody" default:"false"`
	// regex to match againsts the body
	BodyRegex string `json:"bodyRegex" default:".*"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a imap check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{
		Timestamp: time.Now(),
	}

	definitionBytes, err := checks.TemplateDefinition(d, static)
	if err != nil {
		result.Message = fmt.Sprintf("internal error templating definition: %s", err.Error())
		return
	}

	var definition Definition
	err = json.Unmarshal(definitionBytes, &definition)
	if err != nil {
		result.Message = fmt.Sprintf("internal error unmarshaling templated definition: %s", err.Error())
		return
	}

	dialOptions := imapclient.Options{
		TLSConfig: &tls.Config{
			ServerName:         definition.Host,
			InsecureSkipVerify: definition.SkipVerifyCert, // #nosec: G402
		},
	}

	var client *imapclient.Client

	portString := strconv.Itoa(int(definition.Port))
	address := net.JoinHostPort(definition.Host, portString)

	if definition.Encrypted {
		client, err = imapclient.DialTLS(address, &dialOptions)
	} else {
		client, err = imapclient.DialInsecure(address, &dialOptions)
	}
	if err != nil {
		result.Message = fmt.Sprintf("Failed to dial IMAP server: %s", err.Error())
		return
	}

	defer func() {
		logoutErr := client.Logout().Wait()
		if err == nil && logoutErr != nil {
			result.Message = fmt.Sprintf("Failed to logout: %s", logoutErr.Error())
			result.Passed = false
		}
	}()

	if err := client.Login(definition.Username, definition.Password).Wait(); err != nil {
		result.Message = fmt.Sprintf("Failed to login: %s", err.Error())
		return
	}

	mailboxOptions := imap.SelectOptions{
		ReadOnly: true,
	}

	selectedMbox, err := client.Select(definition.Inbox, &mailboxOptions).Wait()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to select inbox %s: %s", definition.Inbox, err.Error())
		return
	}

	// Check if the # of emails is expected
	if definition.MatchMailCount != 0 {
		if selectedMbox.NumMessages != definition.MatchMailCount {
			result.Message = fmt.Sprintf("Mail count does not match: expected %d, found %d", definition.MatchMailCount, selectedMbox.NumMessages)
			return
		}
	}

	// If not comparing emails pass the check
	if definition.MailID == 0 {
		result.Passed = true
		return
	}

	// If the inbox is empty fail the check
	if 0 >= selectedMbox.NumMessages {
		result.Message = "Inbox contains zero messages"
		return
	}

	seqSet := imap.SeqSetNum(uint32(definition.MailID))

	fetchOptions := &imap.FetchOptions{
		Envelope:    true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}

	fetchCmd := client.Fetch(seqSet, fetchOptions)
	defer func() {
		closeErr := fetchCmd.Close()
		if err == nil && closeErr != nil {
			result.Message = fmt.Sprintf("Failed to close message fetch: %s", closeErr.Error())
			result.Passed = false
		}
	}()

	msg := fetchCmd.Next()
	if msg == nil {
		result.Message = "FETCH command did not return any message"
		return
	}

	// Find the body section in the response
	var bodySectionData imapclient.FetchItemDataBodySection
	okay := false
	for {
		item := msg.Next()
		if item == nil {
			break
		}
		bodySectionData, okay = item.(imapclient.FetchItemDataBodySection)
		if okay {
			break
		}
	}
	if !okay {
		result.Message = "FETCH command did not return a body section"
		return
	}

	mr, err := mail.CreateReader(bodySectionData.Literal)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to create mail reader: %s", err.Error())
		return
	}
	defer func() {
		mailReaderClose := mr.Close()
		if err == nil && mailReaderClose != nil {
			result.Message = fmt.Sprintf("Failed to close mail reader: %s", mailReaderClose.Error())
			result.Passed = false
		}
	}()

	if definition.MatchSubject {
		subject, err := mr.Header.Subject()
		if err != nil {
			result.Message = fmt.Sprintf("Failed to retrieve message subject: %s", err.Error())
			return
		}

		regex, err := regexp.Compile(definition.SubjectRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling subject regex string: %s", err)
			return
		}

		if !regex.Match([]byte(subject)) {
			result.Message = "Subject does not match regex"
			return
		}
	}

	if definition.MatchBody {
		var bodyBytes []byte

		// Process the message's parts
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			} else if err != nil {
				result.Message = fmt.Sprintf("Failed to read message part: %s", err.Error())
				return
			}

			switch p.Header.(type) {
			case *mail.InlineHeader:
				bodyBytes, err = io.ReadAll(p.Body)
				if err != nil {
					result.Message = fmt.Sprintf("Failed to read body: %s", err.Error())
					return
				}
			case *mail.AttachmentHeader:
			}
		}

		regex, err := regexp.Compile(definition.BodyRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling body regex string: %s", err)
			return
		}

		if !regex.Match(bodyBytes) {
			result.Message = "Body does not match regex"
			return
		}
	}

	result.Passed = true
	return
}

// Validate checks if the imap definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Username == "" {
		return false, "Username needs to be defined"
	}

	if d.Inbox == "" {
		return false, "Inbox needs to be defined"
	}

	if d.MailID == 0 && (d.MatchSubject || d.SubjectRegex != "" || d.MatchBody || d.BodyRegex != "") {
		return false, "Mail ID must be set to use regex match functionality"
	}

	if d.MatchSubject && d.SubjectRegex != "" {
		if _, err := regexp.Compile(d.SubjectRegex); err != nil {
			return false, "Failed to compile subject regex"
		}
	}

	if d.MatchBody && d.BodyRegex != "" {
		if _, err := regexp.Compile(d.BodyRegex); err != nil {
			return false, "Failed to compile body regex"
		}
	}

	return true, ""
}

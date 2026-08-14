package pop3

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/andrew-aiken/checks"
	"github.com/knadh/go-pop3"
)

type Definition struct {
	// IP or hostname of the host to send the mail to
	Host string `json:"host" optiontype:"required"`
	// TCP port number to connect to
	Port uint16 `json:"port" default:"110"`
	// User that is sending the mail
	Username string `json:"username" optiontype:"required"`
	// The users password
	Password string `json:"password"`
	// If the connection should be encrypted
	Encrypted bool `json:"encrypted" default:"false"`
	// Whether to verify the server's TLS certificate
	SkipVerifyCert bool `json:"skipVerifyCert" default:"false"`
	// Match against the mail count
	// If set to 0 will skip the check
	MatchMailCount uint16 `json:"matchMailCount" default:"0"`
	// Mail id to compare againsts. Defaults to being turned off
	MailID uint16 `json:"mailID" default:"0"`
	// Delete the mail after retrieved
	DeleteMail bool `json:"deleteMail" default:"false"`
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

// Run performs a pop3 check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{
		Timestamp: time.Now(),
	}

	definitionBytes, err := checks.TemplateDefinition(d, static)
	if err != nil {
		result.Message = fmt.Sprintf("internal error templating definition: %s", err)
		return
	}

	var definition Definition
	err = json.Unmarshal(definitionBytes, &definition)
	if err != nil {
		result.Message = fmt.Sprintf("internal error unmarshaling templated definition: %s", err)
		return
	}

	p := pop3.New(pop3.Opt{
		Host:          definition.Host,
		Port:          int(definition.Port),
		TLSEnabled:    definition.Encrypted,
		TLSSkipVerify: definition.SkipVerifyCert,
		DialTimeout:   time.Duration(definition.Timeout) * time.Second,
	})

	c, err := p.NewConn()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to connect: %s\n", err.Error())
		return
	}
	defer c.Quit()

	// Authenticate.
	if err := c.Auth(definition.Username, definition.Password); err != nil {
		result.Message = fmt.Sprintf("Failed to authenticate: %s\n", err.Error())
		return
	}

	if err = c.Noop(); err != nil {
		result.Message = fmt.Sprintf("Noop failed: %s\n", err)
		return
	}

	count, _, err := c.Stat()
	if err != nil {
		result.Message = fmt.Sprintf("Failed to get mail stats: %s", err.Error())
		return
	}

	if definition.MatchMailCount != 0 && count != int(definition.MatchMailCount) {
		result.Message = fmt.Sprintf("Mail count does not match: expected %d, found %d", definition.MatchMailCount, count)
		return
	}

	// If the mail id is 0 pass the check and don't test mail subject/body
	if definition.MailID == 0 {
		result.Passed = true
		return
	}

	msg, err := c.Retr(int(definition.MailID))
	if err != nil {
		result.Message = fmt.Sprintf("Failed to retrieve mail: %s", err.Error())
		return
	}

	if definition.MatchSubject {
		subject := msg.Header.Get("subject")

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
		body, err := io.ReadAll(msg.Body)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to read mail body: %s", err.Error())
			return
		}

		regex, err := regexp.Compile(definition.BodyRegex)
		if err != nil {
			result.Message = fmt.Sprintf("Error compiling body regex string: %s", err)
			return
		}

		if !regex.Match(body) {
			result.Message = "Body does not match regex"
			return
		}
	}

	if definition.DeleteMail {
		if err = c.Dele(int(definition.MailID)); err != nil {
			result.Message = fmt.Sprintf("Failed to delete message: %s", err.Error())
			return
		}
	}

	result.Passed = true
	return
}

// Validate checks if the pop3 definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Username == "" {
		return false, "Username needs to be defined"
	}

	if d.MailID == 0 && (d.DeleteMail || d.MatchSubject || d.SubjectRegex != "" || d.MatchBody || d.BodyRegex != "") {
		return false, "Mail id must be set to use match or delete functionality"
	}

	return true, ""
}

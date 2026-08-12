package git

import (
	"context"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"

	"github.com/andrew-aiken/checks"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
)

type Definition struct {
	// IP or FQDN of the git server
	Host string `json:"host" optiontype:"required"`
	// TCP port number the git server is listening on
	Port uint16 `json:"port" default:"22"`
	// User to authenticate to the git repository
	Username string `json:"username"`
	// The users password
	Password string `json:"password"`
	// Token used for authentication
	Token string `json:"token"`
	// How to connect to the git server
	Protocol string `json:"protocol" default:"https"`
	// Repository path to append to the host
	Path string `json:"path" optiontype:"required"`
	// Target branch to checkout - conflicts with tag
	Branch string `json:"branch" default:"main"`
	// Target tag to checkout - conflicts with branch
	Tag string `json:"tag"`
	// Whether to skip verification of the server's TLS certificate
	TLSSkipVerify bool `json:"tlsSkipVerify" default:"false"`
	// File to retrieve from the git repository
	File string `json:"file"`
	// Whether the file must match a defined regex for the check to pass
	MatchContent bool `json:"matchContent" default:"false"`
	// Regex to match against the returned file  --- TODO file or content
	ContentRegex string `json:"contentRegex" default:".*"`
	// Whether or not to compare the head commit hash
	MatchHeadHash bool `json:"matchHeadHash" default:"false"`
	// The hash digest of the commit
	HeadHash string `json:"headHash"`
	// Whether or not to match a hash of the file contents
	MatchContentHash bool `json:"matchContentHash" default:"false"`
	// The sha3-256 hash digest of the files contents
	ContentHash string `json:"contentHash"`
	// Shared configuration across all checks
	checks.SharedDefinition
}

// Run performs a git check
func (d Definition) Run(ctx context.Context, static checks.StaticConf) (result checks.Results) {
	result = checks.Results{
		Timestamp: time.Now(),
		Details:   make(map[string]string),
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

	// Filesystem abstraction based on memory
	fs := memfs.New()
	// Git objects storer based on memory
	storer := memory.NewStorage()

	cloneOptions, err := generateCloneOptions(definition)
	if err != nil {
		result.Message = fmt.Sprintf("Failed to generate clone options: %s", err)
		return
	}

	repo, err := git.CloneContext(ctx, storer, fs, &cloneOptions)
	if err != nil {
		result.Message = fmt.Sprintf("Failed clone repository: %s", err)
		return
	}

	if definition.File != "" {
		file, err := fs.Open(definition.File)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to open file: %s", err)
			return
		}
		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			result.Message = fmt.Sprintf("Failed to read file: %s", err)
			return
		}

		// Compare the files content against a regular expression
		if definition.MatchContent {
			regex, err := regexp.Compile(definition.ContentRegex)
			if err != nil {
				result.Message = fmt.Sprintf("Error compiling regex string: %s", err)
				return
			}
			if !regex.Match(content) {
				result.Message = "File contents does not match regex"
				return
			}
		}

		// Compare the files content against as hash
		if definition.MatchContentHash {
			digest := sha3.Sum256(content)

			// Check if the digest of the file matches the defined hash
			if digestString := hex.EncodeToString(digest[:]); digestString != definition.ContentHash {
				result.Message = "File content does not match hash"
				result.Details["hash"] = digestString
				return
			}
		}
	}

	// Compare the head commit
	if definition.MatchHeadHash {
		repoHead, err := repo.Head()
		if err != nil {
			result.Message = fmt.Sprintf("Failed to get head of branch: %s", err)
			return
		}

		digest := repoHead.Hash()

		// Check if the digest of the file matches the defined hash
		if digestString := hex.EncodeToString(digest[:]); digestString != definition.HeadHash {
			result.Message = "Branch head commit does not match"
			result.Details["hash"] = digestString
			return
		}
	}

	result.Passed = true
	return
}

// Validate checks if the git definition is valid
func (d Definition) Validate() (passed bool, message string) {
	if d.Host == "" {
		return false, "Host needs to be defined"
	}

	if d.Path == "" {
		return false, "Path needs to be defined"
	}

	if d.Password != "" && d.Token != "" {
		return false, "Either token, password, or neither should be set"
	}

	if d.Branch != "" && d.Tag != "" {
		return false, "Either branch or tag should be set"
	}

	items := []string{"", "ssh", "https"}
	if !slices.Contains(items, d.Protocol) {
		return false, "Invalid protocol option specified"
	}

	if d.MatchContent {
		if d.File == "" {
			return false, "File must be specified when matching content"
		}
		if d.ContentRegex != "" {
			if _, err := regexp.Compile(d.ContentRegex); err != nil {
				return false, "Failed to compile regex"
			}
		}
	}

	if d.MatchContentHash {
		if d.ContentHash == "" {
			return false, "Must specify hash when matching content hash is set"
		}
		if d.File == "" {
			return false, "Must specify file when matching content hash is set"
		}
	}

	return true, ""
}

// generateCloneOptions wraps the process of generating the go-git clone options
func generateCloneOptions(d Definition) (cloneOptions git.CloneOptions, err error) {
	repoUrlRaw := transport.Endpoint{
		Host:            d.Host,
		Port:            int(d.Port),
		Path:            d.Path,
		Protocol:        d.Protocol,
		User:            d.Username,
		Password:        d.Password,
		InsecureSkipTLS: d.TLSSkipVerify,
	}

	repoUrl, err := transport.NewEndpoint(repoUrlRaw.String())
	if err != nil {
		return
	}

	var targetRef plumbing.ReferenceName
	if d.Tag != "" {
		targetRef = plumbing.NewTagReferenceName(d.Tag)
	} else {
		targetRef = plumbing.NewBranchReferenceName(d.Branch)
	}

	cloneOptions = git.CloneOptions{
		URL:             repoUrl.String(),
		RemoteName:      "origin",
		Depth:           1,
		ReferenceName:   targetRef,
		SingleBranch:    true,
		InsecureSkipTLS: d.TLSSkipVerify,
	}

	if d.File == "" && !d.MatchHeadHash {
		cloneOptions.NoCheckout = true
	}

	// Setup authentication
	if d.Token != "" {
		cloneOptions.Auth = &http.BasicAuth{
			Username: "placeholder",
			Password: d.Token,
		}
	} else if d.Username != "" && d.Password != "" {
		cloneOptions.Auth = &http.BasicAuth{
			Username: d.Username,
			Password: d.Password,
		}
	}

	err = cloneOptions.Validate()

	return
}

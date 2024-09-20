package snyk

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Ignore represents an ignore of a Snyk issue
type Ignore struct {
	Reason             string     `json:"reason"`
	Created            time.Time  `json:"created"`
	Expires            *time.Time `json:"expires"`
	IgnoredBy          ignoredBy  `json:"ignoredBy"`
	ReasonType         string     `json:"reasonType"`
	DisregardIfFixable bool       `json:"disregardIfFixable"`
	Path               []struct {
		Module string `json:"module"`
	} `json:"path,omitempty"`
}

type ignoreByPath map[string]Ignore

// IgnoredIssuesByPath is a map of ignored issues by their issue ID and ignored paths
type IgnoredIssuesByPath map[string][]ignoreByPath

// toIgnoredIssues converts the IgnoredIssuesByPath type into the IgnoredIssues type
func (i *IgnoredIssuesByPath) toIgnoredIssues() IgnoredIssues {
	ignoredIssues := IgnoredIssues{}

	for issueID, ignoresByPath := range *i {
		for _, ignorePath := range ignoresByPath {
			for path, ignore := range ignorePath {
				ignore.Path = append(ignore.Path, struct {
					Module string `json:"module"`
				}{Module: path},
				)
				ignoredIssues[issueID] = append(ignoredIssues[issueID], ignore)
			}
		}
	}

	return ignoredIssues
}

// IgnoredIssues is a map of issue IDs and ignores
type IgnoredIssues map[string][]Ignore

// GetIgnored gets all ignored issues
func (s *ProjectIssuesService) GetIgnored() (IgnoredIssues, error) {
	path := fmt.Sprintf("/v1/org/%s/project/%s/ignores", s.orgID, s.projectID)

	resp, err := s.client.Get(path, nil)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Snyk returns a different datatype for ignores on some projects. This will coerce
	// all responses in to the same type

	// Try to parse the response using the first type
	respBody := IgnoredIssuesByPath{}
	err = json.Unmarshal(bodyBytes, &respBody)
	if err != nil {
		// If it fails, try the second type
		respBody := IgnoredIssues{}
		err = json.Unmarshal(bodyBytes, &respBody)
		if err != nil {
			return nil, errors.New("Failed to parse ignore response body")
		}

		return respBody, nil
	}

	return respBody.toIgnoredIssues(), nil
}

// GetIgnore gets the ignore data for the issue
func (i *Issue) GetIgnore() (Ignore, error) {
	path := fmt.Sprintf("/v1/org/%s/project/%s/ignore/%s", i.orgID, i.projectID, i.ID)

	resp, err := i.client.Get(path, nil)
	if err != nil {
		return Ignore{}, err
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Ignore{}, err
	}

	respBody := Ignore{}
	err = json.Unmarshal(bodyBytes, &respBody)
	if err != nil {
		return Ignore{}, errors.New("Failed to parse ignore response body")
	}

	return respBody, nil
}

// IgnoreOptions defines how an issue should be ignored
type IgnoreOptions struct {
	// The path to ignore (default is * which represents all paths)
	IgnorePath string `json:"ignorePath,omitempty"`
	// The reason that the issue was ignored
	Reason string `json:"reason,omitempty"`
	// The classification of the ignore.
	// Must be one of `not-vulnerable`, `wont-fix`, `temporary-ignore`
	ReasonType string `json:"reasonType,omitempty"`
	// Only ignore the issue if no upgrade or patch is available
	DisregardIfFixable bool `json:"disregardIfFixable"`
	// The timestamp that the issue will no longer be ignored
	Expires string `json:"expires,omitempty"`
}

// AddIgnore adds an ignores for the specified issue according to `IgnoreOptions`
func (i *Issue) AddIgnore(opts IgnoreOptions) error {
	if opts.ReasonType != "not-vulnerable" && opts.ReasonType != "wont-fix" && opts.ReasonType != "temporary-ignore" {
		return errors.New("ReasonType must be one of \"not-vulnerable\", \"wont-fix\", \"temporary-ignore\"")
	}

	path := fmt.Sprintf("v1/org/%s/project/%s/ignore/%s", i.orgID, i.projectID, i.ID)

	_, err := i.client.Post(path, nil, opts)
	return err
}

// ReplaceIgnore replaces an existing ignore with the new ignore
func (i *Issue) ReplaceIgnore(opts IgnoreOptions) error {
	if opts.ReasonType != "not-vulnerable" && opts.ReasonType != "wont-fix" && opts.ReasonType != "temporary-ignore" {
		return errors.New("ReasonType must be one of \"not-vulnerable\", \"wont-fix\", \"temporary-ignore\"")
	}

	path := fmt.Sprintf("v1/org/%s/project/%s/ignore/%s", i.orgID, i.projectID, i.ID)

	_, err := i.client.Put(path, opts)
	return err
}

// DeleteIgnore deletes ignores for a given issue
func (i *Issue) DeleteIgnore() error {
	path := fmt.Sprintf("v1/org/%s/project/%s/ignore/%s", i.orgID, i.projectID, i.ID)

	_, err := i.client.Delete(path, nil)
	return err
}

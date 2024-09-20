package snyk

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// Issue represents an issue in a Snyk project
type Issue struct {
	ID            string   `json:"id"`
	IssueType     string   `json:"issueType"`
	PkgName       string   `json:"pkgName"`
	PkgVersions   []string `json:"pkgVersions"`
	PriorityScore int      `json:"priorityScore"`
	Priority      struct {
		Score   int      `json:"score"`
		Factors []factor `json:"factors"`
	} `json:"priority"`
	IssueData struct {
		ID                    string           `json:"id"`
		Title                 string           `json:"title"`
		Severity              string           `json:"severity"`
		URL                   string           `json:"url"`
		Description           string           `json:"description"`
		Identifiers           issueIdentifiers `json:"identifiers"`
		Credit                []string         `json:"credit"`
		ExploitMaturity       string           `json:"exploitMaturity"`
		SemVer                any              `json:"semver"`
		PublicationTime       time.Time        `json:"publicationTime"`
		DisclosureTime        time.Time        `json:"disclosureTime"`
		CVSSv3                string           `json:"CVSSv3"`
		CVSSScore             float32          `json:"cvssScore"`
		Language              string           `json:"language"`
		Patches               []patch          `json:"patches"`
		NearestFixedInVersion string           `json:"nearestFixedInVersion"`
		IsMaliciousPackage    bool             `json:"isMaliciousPackage"`
	} `json:"issueData"`
	IsPatched     bool           `json:"isPatched"`
	IsIgnored     bool           `json:"isIgnored"`
	IgnoreReasons []ignoreReason `json:"ignoreReasons"`
	FixInfo       struct {
		IsUpgradable          bool     `json:"isUpgradable"`
		IsPinnable            bool     `json:"isPinnable"`
		IsPatchable           bool     `json:"isPatchable"`
		IsFixable             bool     `json:"isFixable"`
		IsPartiallyFixable    bool     `json:"isPartiallyFixable"`
		NearestFixedInVersion string   `json:"nearestFixedInVersion"`
		FixedIn               []string `json:"fixedIn"`
	} `json:"fixInfo"`
	Link struct {
		Paths string `json:"paths"`
	} `json:"links"`
	orgID         string
	projectID     string
	projectOrigin string
	client        *Client
}

type factor struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type issuesResp struct {
	Issues []Issue `json:"issues"`
}

type issueIdentifiers struct {
	CVE  []string `json:"CVE"`
	CWE  []string `json:"CWE"`
	GHSA []string `json:"GHSA"`
}

type patch struct {
	ID               string    `json:"id"`
	URLs             []string  `json:"urls"`
	Version          string    `json:"version"`
	Comments         []string  `json:"comments"`
	ModificationTime time.Time `json:"modificationTime"`
}

type ignoreReason struct {
	Path               []string  `json:"path"`
	Reason             string    `json:"reason"`
	Source             string    `json:"source"`
	IgnoredBy          ignoredBy `json:"ignoredBy"`
	ReasonType         string    `json:"reasonType"`
	DisregardIfFixable bool      `json:"disregardIfFixable"`
}

type ignoredBy struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// ProjectIssuesService handles requests for Issue resources on the given Project
type ProjectIssuesService struct {
	client        *Client
	projectID     string
	projectOrigin string
	orgID         string
}

// GetAll gets all issues for the given project
func (s *ProjectIssuesService) GetAll() ([]Issue, error) {
	var issues []Issue
	path := fmt.Sprintf("/v1/org/%s/project/%s/aggregated-issues", s.orgID, s.projectID)
	params := url.Values{}
	params.Set("includeIntroducedThrough", "true")
	params.Set("includeDescription", "true")
	resp, err := s.client.Post(path, params, nil)
	if err != nil {
		return nil, err
	}

	respBody := issuesResp{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return issues, err
	}

	for _, issue := range respBody.Issues {
		issue.orgID = s.orgID
		issue.projectID = s.projectID
		issue.projectOrigin = s.projectOrigin
		issue.client = s.client
		issues = append(issues, issue)
	}

	return issues, nil
}

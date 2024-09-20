package snyk

import (
	"fmt"
	"net/url"
	"time"
)

// IssueV2 represents a Snyk issue from the newer REST API
type IssueV2 struct {
	ID                     string
	Key                    string
	Title                  string
	Status                 string
	EffectiveSecurityLevel string
	Ignored                bool
	Type                   string
	CreatedAt              *time.Time
	UpdatedAt              *time.Time
	Classes                []Data
	Problems               []Data
	Resolution             resolution
	client                 *Client
	OrgID                  string
	ProjectID              string
}

// OrgIssuesService handles requests for Issue resources on the given Org
type OrgIssuesService struct {
	client *Client
	orgID  string
}

func (r *resource) intoIssueV2(client *Client) IssueV2 {
	org := r.Relationships["organization"]
	project := r.Relationships["scan_item"]

	return IssueV2{
		ID:                     r.ID,
		Key:                    r.Attributes.Key,
		Type:                   r.Attributes.Type,
		Title:                  r.Attributes.Title,
		Status:                 r.Attributes.Status,
		EffectiveSecurityLevel: r.Attributes.EffectiveSeverityLevel,
		Ignored:                r.Attributes.Ignored,
		CreatedAt:              r.Attributes.CreatedAt,
		UpdatedAt:              r.Attributes.UpdatedAt,
		Classes:                r.Attributes.Classes,
		Problems:               r.Attributes.Problems,
		Resolution:             r.Attributes.Resolution,
		client:                 client,
		OrgID:                  org.Data.ID,
		ProjectID:              project.Data.ID,
	}
}

// intoIssueV1 converts an `IssueV2` into an `Issue` so methods implemented on the V1 type can be used on V2 types.
// Only some fields are able to be mapped to the V1 type
func (i *IssueV2) intoIssueV1() Issue {
	return Issue{
		ID:        i.Key,
		IssueType: i.Type,
		IsIgnored: i.Ignored,
		orgID:     i.OrgID,
		projectID: i.ProjectID,
		client:    i.client,
	}
}

func getAllV2Issues(client *Client, orgID string, projectID *string) ([]IssueV2, error) {
	var issues []IssueV2
	path := fmt.Sprintf("/rest/orgs/%s/issues", orgID)
	params := url.Values{}
	params.Add("version", "2024-05-23~beta")
	if projectID != nil {
		params.Add("scan_item.type", "project")
		params.Add("scan_item.id", *projectID)
	}
	resources, err := getMultiResource(client, path, params)
	if err != nil {
		return nil, err
	}

	for _, r := range resources {
		issues = append(issues, r.intoIssueV2(client))
	}

	return issues, nil
}

// GetAllV2 gets all IssueV2s for the org.
func (s *OrgIssuesService) GetAllV2() ([]IssueV2, error) {
	return getAllV2Issues(s.client, s.orgID, nil)
}

// GetAllV2 gets all IssueV2s for the project
func (s *ProjectIssuesService) GetAllV2() ([]IssueV2, error) {
	return getAllV2Issues(s.client, s.orgID, &s.projectID)
}

// GetIgnore gets the ignore data for the issue
func (i *IssueV2) GetIgnore() (Ignore, error) {
	issueV1 := i.intoIssueV1()
	return issueV1.GetIgnore()
}

// AddIgnore adds an ignores for the specified issue according to `IgnoreOptions`
func (i *IssueV2) AddIgnore(opts IgnoreOptions) error {
	issueV1 := i.intoIssueV1()
	return issueV1.AddIgnore(opts)
}

// ReplaceIgnore replaces an existing ignore with the new ignore
func (i *IssueV2) ReplaceIgnore(opts IgnoreOptions) error {
	issueV1 := i.intoIssueV1()
	return issueV1.ReplaceIgnore(opts)
}

// DeleteIgnore deletes ignores for a given issue
func (i *IssueV2) DeleteIgnore() error {
	issueV1 := i.intoIssueV1()
	return issueV1.DeleteIgnore()
}

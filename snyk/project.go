package snyk

import (
	"fmt"
	"net/url"
	"time"
)

// Project represents a project on an Org
type Project struct {
	ID                  string
	Name                string
	Type                string
	TargetFile          string
	TargetReference     string
	Origin              string
	Created             time.Time
	Status              string
	BusinessCriticality []string
	Environment         []string
	Lifecycle           []string
	Tags                []tag
	ReadOnly            bool
	Meta                meta
	Relationships       map[string]Relationship
	Issues              ProjectIssuesService
	orgID               string
	client              *Client
}

// ProjectsService handles requests for Project resources on the given Org
type ProjectsService struct {
	client *Client
	orgID  string
}

func (r *resource) intoProject(client *Client, orgID string) Project {
	return Project{
		ID:                  r.ID,
		Name:                r.Attributes.Name,
		Type:                r.Attributes.Type,
		TargetFile:          r.Attributes.TargetFile,
		TargetReference:     r.Attributes.TargetReference,
		Origin:              r.Attributes.Origin,
		Created:             r.Attributes.Created,
		Status:              r.Attributes.Status,
		BusinessCriticality: r.Attributes.BusinessCriticality,
		Environment:         r.Attributes.Environment,
		Lifecycle:           r.Attributes.Lifecycle,
		Tags:                r.Attributes.Tags,
		ReadOnly:            r.Attributes.ReadOnly,
		Meta:                r.Meta,
		Relationships:       r.Relationships,
		Issues: ProjectIssuesService{
			client:        client,
			projectID:     r.ID,
			projectOrigin: r.Attributes.Origin,
			orgID:         orgID,
		},
		orgID:  orgID,
		client: client,
	}
}

// GetAll gets all projects for the org
func (s *ProjectsService) GetAll() ([]Project, error) {
	var projects []Project
	path := fmt.Sprintf("/rest/orgs/%s/projects", s.orgID)
	params := url.Values{}
	params.Add("meta.latest_dependency_total", "true")
	params.Add("meta.latest_issue_counts", "true")
	resources, err := getMultiResource(s.client, path, params)
	if err != nil {
		return nil, err
	}

	for _, r := range resources {
		projects = append(projects, r.intoProject(s.client, s.orgID))
	}

	return projects, nil
}

// Get gets the project specified by the given `id`
func (s *ProjectsService) Get(id string) (Project, error) {
	var project Project
	path := fmt.Sprintf("/rest/orgs/%s/projects/%s", s.orgID, id)
	res, err := getSingleResource(s.client, path, nil)
	if err != nil {
		return project, err
	}

	return res.intoProject(s.client, s.orgID), nil
}

// Delete deletes the given project from Snyk
func (p *Project) Delete() error {
	path := fmt.Sprintf("v1/org/%s/project/%s", p.orgID, p.ID)
	_, err := p.client.Delete(path, nil)
	return err
}

// Deactivate deactivates the given project from Snyk
func (p *Project) Deactivate() error {
	path := fmt.Sprintf("v1/org/%s/project/%s/deactivate", p.orgID, p.ID)
	_, err := p.client.Post(path, nil, nil)
	return err
}

// Move moves a project from it's parent org to the provided org
func (p *Project) Move(targetOrdID string) error {
	type reqBody struct {
		TargetOrgID string `json:"targetOrgId"`
	}

	path := fmt.Sprintf("v1/org/%s/project/%s/move", p.orgID, p.ID)
	body := reqBody{TargetOrgID: targetOrdID}

	_, err := p.client.Put(path, body)
	return err
}

// ScanType returns the scan type for a Snyk Project.
//
// Returns "container" for "deb", "linux", "dockerfile", "rpm", and "apk" scans.
// Returns "iac" for "k8sconfig", "helmconfig", "terraformconfig", "armconfig", and "cloudformationconfig" scans.
// Return "sast" for "sast" scans.
// Returns "opensource" for all others.
func (p *Project) ScanType() string {
	containerTypes := []string{"deb", "linux", "dockerfile", "rpm", "apk"}
	iacTypes := []string{
		"k8sconfig",
		"helmconfig",
		"terraformconfig",
		"armconfig",
		"cloudformationconfig",
		"cloudconfig",
	}
	codeTypes := []string{"sast"}

	if isInSlice(p.Type, containerTypes) {
		return "container"
	} else if isInSlice(p.Type, iacTypes) {
		return "iac"
	} else if isInSlice(p.Type, codeTypes) {
		return "sast"
	}
	return "opensource"
}

func isInSlice[T comparable](item T, slice []T) bool {
	for _, value := range slice {
		if item == value {
			return true
		}
	}
	return false
}

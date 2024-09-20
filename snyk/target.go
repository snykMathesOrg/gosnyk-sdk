package snyk

import (
	"fmt"
	"net/url"
)

// Target represents a scan target on an Org
type Target struct {
	ID          string
	DisplayName string
	Origin      string
	RemoteURL   string
	IsPrivate   bool
	client      *Client
	orgID       string
}

// TargetsService handles requests for Target resources on the given Org
type TargetsService struct {
	client *Client
	orgID  string
}

func (r *resource) intoTarget(client *Client, orgID string) Target {
	return Target{
		ID:          r.ID,
		DisplayName: r.Attributes.DisplayName,
		Origin:      r.Attributes.Origin,
		RemoteURL:   r.Attributes.RemoteURL,
		IsPrivate:   r.Attributes.IsPrivate,
		client:      client,
		orgID:       orgID,
	}
}

// GetAll gets all targets for the org
func (s *TargetsService) GetAll() ([]Target, error) {
	var targets []Target
	params := url.Values{}
	params.Set("version", "2024-01-23~beta")
	params.Set("excludeEmpty", "false")
	path := fmt.Sprintf("/rest/orgs/%s/targets", s.orgID)

	resources, err := getMultiResource(s.client, path, params)
	if err != nil {
		return nil, err
	}

	for _, r := range resources {
		targets = append(targets, r.intoTarget(s.client, s.orgID))
	}

	return targets, nil
}

// Get gets the target specified by the given `id`
func (s *TargetsService) Get(id string) (Target, error) {
	var target Target
	path := fmt.Sprintf("/rest/orgs/%s/targets/%s", s.orgID, id)
	res, err := getSingleResource(s.client, path, nil)
	if err != nil {
		return target, err
	}

	return res.intoTarget(s.client, s.orgID), nil
}

// GetByRemoteURL gets the target specified by the given `remoteURL`
func (s *TargetsService) GetByRemoteURL(remoteURL string) ([]Target, error) {
	var targets []Target
	path := fmt.Sprintf("/rest/orgs/%s/targets", s.orgID)
	params := url.Values{}
	params.Add("remoteUrl", remoteURL)

	resources, err := getMultiResource(s.client, path, params)
	if err != nil {
		return targets, err
	}

	for _, r := range resources {
		targets = append(targets, r.intoTarget(s.client, s.orgID))
	}

	return targets, nil
}

// Delete deletes the target
func (t *Target) Delete() error {
	path := fmt.Sprintf("/rest/orgs/%s/targets/%s", t.orgID, t.ID)
	params := url.Values{}
	params.Add("version", "2024-01-23~beta")
	_, err := t.client.Delete(path, params)
	return err
}

package snyk

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
)

// Org represents a Snyk Organization
type Org struct {
	ID              string
	Name            string
	Slug            string
	Projects        ProjectsService
	Targets         TargetsService
	ContainerImages ContainerImagesService
	Issues          OrgIssuesService
	client          *Client
}

// OrgsService handles requests for Org endpoints on the Snyk API
type OrgsService service

func (r *resource) intoOrg(client *Client) Org {
	return Org{
		ID:   r.ID,
		Name: r.Attributes.Name,
		Slug: r.Attributes.Slug,
		Projects: ProjectsService{
			client: client,
			orgID:  r.ID,
		},
		Targets: TargetsService{
			client: client,
			orgID:  r.ID,
		},
		ContainerImages: ContainerImagesService{
			client: client,
			orgID:  r.ID,
		},
		Issues: OrgIssuesService{
			client: client,
			orgID:  r.ID,
		},
		client: client,
	}
}

// GetAll gets all available organizations
func (s *OrgsService) GetAll() ([]Org, error) {
	var orgs []Org
	resources, err := getMultiResource(s.client, "/rest/orgs", nil)
	if err != nil {
		return nil, err
	}

	for _, r := range resources {
		orgs = append(orgs, r.intoOrg(s.client))
	}

	return orgs, nil
}

// Get gets the organization specified by the `identifier` parameter
// If `identifier` is a UUID, the org is fetched by it's ID. Otherwise, it is assumed that `identifier` is an org slug
func (s *OrgsService) Get(identifier string) (Org, error) {
	var path string
	params := url.Values{}
	if isUUID(identifier) {
		path = fmt.Sprintf("/rest/orgs/%s", identifier)
		resp, err := getSingleResource(s.client, path, params)
		if err != nil {
			return Org{}, err
		}
		return resp.intoOrg(s.client), nil
	}

	path = fmt.Sprintf("/rest/orgs")
	params.Set("slug", identifier)

	multiResp, err := getMultiResource(s.client, path, params)
	if err != nil {
		return Org{}, err
	}

	if len(multiResp) == 0 {
		return Org{}, fmt.Errorf("No org found for slug '%s'", identifier)
	}

	return multiResp[0].intoOrg(s.client), nil
}

// Create creates a Snyk org. sourceOrgID can optionally be passed to clone the org from another org
func (s *OrgsService) Create(groupID, name string, sourceOrgID *string) (Org, error) {
	type RequestBody struct {
		Name        string `json:"name"`
		GroupID     string `json:"groupId"`
		SourceOrgID string `json:"sourceOrgId,omitempty"`
	}

	body := RequestBody{
		Name:        name,
		GroupID:     groupID,
		SourceOrgID: *sourceOrgID,
	}

	resp, err := s.client.Post("/v1/org", nil, body)
	if err != nil {
		return Org{}, fmt.Errorf("Failed to create org: %s", err.Error())
	}

	type NewOrg struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	}

	respBody := NewOrg{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return Org{}, err
	}

	newOrg := Org{
		ID:   respBody.ID,
		Name: respBody.Name,
		Slug: respBody.Slug,
		Projects: ProjectsService{
			client: s.client,
			orgID:  respBody.ID,
		},
		Targets: TargetsService{
			client: s.client,
			orgID:  respBody.ID,
		},
		client: s.client,
	}

	return newOrg, nil
}

// UpdateUserRole sets the given `user`'s role to the given `roleId`
func (o *Org) UpdateUserRole(user User, roleID string) error {
	urlPath := fmt.Sprintf("/v1/org/%s/members/update/%s", o.ID, user.ID)
	body := map[string]string{"rolePublicId": roleID}

	_, err := o.client.Put(urlPath, body)
	if err != nil {
		return fmt.Errorf("Failed to update user role; %s", err.Error())
	}

	return nil
}

// OrgSettings defines the configurable settings for a Snyk Org
type OrgSettings struct {
	RequestAccess struct {
		// Whether requesting access to the organization is enabled.
		Enabled bool `json:"enabled"`
	} `json:"requestAccess,omitempty"`
}

// GetSettings returns the currently configured settings for the given org
func (o *Org) GetSettings() (OrgSettings, error) {
	urlPath := fmt.Sprintf("/v1/org/%s/settings", o.ID)
	settings := OrgSettings{}
	resp, err := o.client.Get(urlPath, nil)
	if err != nil {
		return settings, fmt.Errorf("Failed to get org settings; %s", err.Error())
	}
	err = json.NewDecoder(resp.Body).Decode(&settings)
	if err != nil {
		return settings, fmt.Errorf("Failed to get org settings; %s", err.Error())
	}

	return settings, nil
}

// UpdateSettings updates the provided settings on the given org
func (o *Org) UpdateSettings(settings OrgSettings) error {
	urlPath := fmt.Sprintf("/v1/org/%s/settings", o.ID)

	_, err := o.client.Put(urlPath, settings)
	if err != nil {
		return fmt.Errorf("Failed to update org settings; %s", err.Error())
	}

	return nil
}

// GetIntegrations returns a map of all configured integrations for the org.
// The integration name is the key and the integration ID is the value.
func (o *Org) GetIntegrations() (map[string]string, error) {
	urlPath := fmt.Sprintf("/v1/org/%s/integrations", o.ID)

	resp, err := o.client.Get(urlPath, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to get org integrations; %s", err.Error())
	}

	integrations := make(map[string]string)

	err = json.NewDecoder(resp.Body).Decode(&integrations)
	if err != nil {
		return nil, fmt.Errorf("Failed to get org integrations; %s", err.Error())
	}

	return integrations, nil
}

// CloneIntegration clones an integration from the org to the given `destinationOrgID`
func (o *Org) CloneIntegration(integrationID, destinationOrgID string) (string, error) {
	urlPath := fmt.Sprintf("/v1/org/%s/integrations/%s/clone", o.ID, integrationID)

	body := make(map[string]string)
	body["destinationOrgPublicId"] = destinationOrgID

	resp, err := o.client.Post(urlPath, nil, body)

	respBody := make(map[string]string)

	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return "", fmt.Errorf("Failed to clone integration; %s", err.Error())
	}

	return respBody["newIntegrationId"], nil
}

// ImportTarget defines a new target to import into Snyk
type ImportTarget struct {
	Target struct {
		// for Github: account owner of the repository; for Azure Repos, this is Project ID
		Owner string `json:"owner,omitempty"`
		// name of the repo
		Name string `json:"name,omitempty"`
		// default branch of the repo
		Branch string `json:"branch,omitempty"`
	} `json:"target"`

	Files []struct {
		Path map[string]string `json:"path,omitempty"`
	} `json:"files,omitempty"`

	// a comma-separated list of up to 10 folder names to exclude from scanning (each folder name
	// must not exceed 100 characters). If not specified, it will default to "fixtures, tests,
	// __tests__, node_modules". If an empty string is provided - no folders will be excluded. This
	// attribute is only respected with Open Source and Container scan targets.
	ExclusionGlobs string `json:"exclusionGlobs,omitempty"`
}

// ImportProject imports the provided target to Snyk using the given `integrationID`
func (o *Org) ImportProject(integrationID string, importTarget ImportTarget) error {
	urlPath := fmt.Sprintf("/v1/org/%s/integrations/%s/import", o.ID, integrationID)

	_, err := o.client.Post(urlPath, nil, importTarget)
	if err != nil {
		return fmt.Errorf("Failed to import target; %s", err.Error())
	}

	return nil
}

func isUUID(value string) bool {
	uuidPattern := `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`
	re := regexp.MustCompile(uuidPattern)
	return re.MatchString(value)
}

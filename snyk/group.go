package snyk

import (
	"fmt"
)

// Group represents a Snyk Group
type Group struct {
	ID     string
	Name   string
	client *Client
}

// GroupsService handles requests for Group resources
type GroupsService service

func (r *resource) intoGroup(client *Client) Group {
	return Group{
		ID:     r.ID,
		Name:   r.Attributes.Name,
		client: client,
	}
}

// GetAll fetches all groups from Snyk
func (s *GroupsService) GetAll() ([]Group, error) {
	var groups []Group
	path := "/rest/groups"
	resources, err := getMultiResource(s.client, path, nil)
	if err != nil {
		return nil, err
	}

	for _, r := range resources {
		groups = append(groups, r.intoGroup(s.client))
	}

	return groups, nil
}

// Get fetches a group from Snyk with the given `groupID`
func (s *GroupsService) Get(groupID string) (Group, error) {
	path := fmt.Sprintf("/rest/groups/%s", groupID)
	res, err := getSingleResource(s.client, path, nil)
	if err != nil {
		return Group{}, err
	}

	group := res.intoGroup(s.client)

	return group, nil
}

// AddUserToOrg adds the given user to the given org within the group. `role` must be one of "admin" or "collaborator"
func (g *Group) AddUserToOrg(org Org, user User, role string) error {
	urlPath := fmt.Sprintf("/v1/group/%s/org/%s/members", g.ID, org.ID)
	body := map[string]string{"userId": user.ID, "role": role}

	_, err := g.client.Post(urlPath, nil, body)
	if err != nil {
		return fmt.Errorf("Failed to add user to org; %s", err.Error())
	}

	return nil
}

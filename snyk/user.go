package snyk

import (
	"encoding/json"
	"fmt"
)

// User represents a user in Snyk
type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Orgs     []struct {
		Name string `json:"name"`
		Role string `json:"role"`
	} `json:"orgs"`
	GroupRole string `json:"groupRole"`
}

// UsersService handles requests for Project resources on the given Org
type UsersService service

// GetAll returns all user in the given group
func (s *UsersService) GetAll(groupID string) ([]User, error) {
	var users []User
	urlPath := fmt.Sprintf("/v1/group/%s/members", groupID)
	resp, err := s.client.Get(urlPath, nil)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resp.Body).Decode(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

package snyk

import (
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/h2non/gock"
)

func TestGroupGetAll(t *testing.T) {
	defer gock.Off()

	respJSON, err := loadFixture("fixtures/group_get_all.json")
	assert.NoError(t, err)

	gock.New(baseURL).
		Get("/rest/groups").
		MatchParam("version", defaultAPIVersion).
		Reply(200).
		JSON(respJSON)

	client := NewClient("mock-token")
	groups, err := client.Groups.GetAll()
	assert.NoError(t, err)
	assert.Equal(t, 1, len(groups))
	assert.Equal(t, "Group1", groups[0].Name)
	assert.Equal(t, "341bdf0c-05d3-47d4-b522-97ba9552b796", groups[0].ID)
}

func TestGroupGet(t *testing.T) {
	defer gock.Off()

	respJSON, err := loadFixture("fixtures/group_get.json")
	assert.NoError(t, err)

	gock.New(baseURL).
		Get("/rest/groups/341bdf0c-05d3-47d4-b522-97ba9552b796").
		MatchParam("version", defaultAPIVersion).
		Reply(200).
		JSON(respJSON)

	client := NewClient("mock-token")
	group, err := client.Groups.Get("341bdf0c-05d3-47d4-b522-97ba9552b796")
	assert.NoError(t, err)
	assert.Equal(t, "Group1", group.Name)
	assert.Equal(t, "341bdf0c-05d3-47d4-b522-97ba9552b796", group.ID)
}

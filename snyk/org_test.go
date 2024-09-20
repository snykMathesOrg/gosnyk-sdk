package snyk

import (
	"fmt"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/h2non/gock"
)

const (
	testOrgID = "8bcff720-99a4-4442-bb35-31f7a74d27b0"
)

func TestOrgGet(t *testing.T) {
	defer gock.Off()

	respJSON, err := loadFixture("fixtures/org_get.json")
	assert.NoError(t, err)

	gock.New(baseURL).
		Get(fmt.Sprintf("/rest/orgs/%s", testOrgID)).
		MatchParam("version", defaultAPIVersion).
		Reply(200).
		JSON(respJSON)

	client := NewClient("mock-token")
	org, err := client.Orgs.Get(testOrgID)
	assert.NoError(t, err)
	assert.Equal(t, "org1", org.Name)
	assert.Equal(t, "org1-abc", org.Slug)
	assert.Equal(t, testOrgID, org.ID)
}

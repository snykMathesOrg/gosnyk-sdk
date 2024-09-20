package snyk

import (
	"fmt"
	"testing"

	"github.com/alecthomas/assert/v2"
	"github.com/h2non/gock"
)

func TestContainerImageGetAll(t *testing.T) {
	defer gock.Off()

	respJSONorg, err := loadFixture("fixtures/org_get.json")
	assert.NoError(t, err)

	respJSONp1, err := loadFixture("fixtures/container_image_get_all_page1.json")
	assert.NoError(t, err)

	respJSONp2, err := loadFixture("fixtures/container_image_get_all_page2.json")
	assert.NoError(t, err)

	gock.New(baseURL).
		Get(fmt.Sprintf("/rest/orgs/%s", testOrgID)).
		MatchParam("version", defaultAPIVersion).
		Reply(200).
		JSON(respJSONorg)

	gock.New(baseURL).
		Get(fmt.Sprintf("/rest/orgs/%s/container_images", testOrgID)).
		MatchParam("version", "2024-01-23~beta").
		Reply(200).
		JSON(respJSONp1)

	gock.New(baseURL).
		Get(fmt.Sprintf("/rest/orgs/%s/container_images", testOrgID)).
		MatchParam("version", "2024-01-23~beta").
		MatchParam("starting_after", "v2.mXj4PTbNK6N_N7K3lcYwjZvuYLBeeSCSNfK9EznyHAo=").
		Reply(200).
		JSON(respJSONp2)

	client := NewClient("mock-token")
	org, err := client.Orgs.Get(testOrgID)
	assert.NoError(t, err)

	images, err := org.ContainerImages.GetAll()
	assert.NoError(t, err)

	assert.Equal(t, 12, len(images))
}

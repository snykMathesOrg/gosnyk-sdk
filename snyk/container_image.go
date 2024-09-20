package snyk

import (
	"fmt"
	"net/url"
)

// ContainerImage represents a scanned container image
type ContainerImage struct {
	ID       string
	Layers   []string
	Names    []string
	Platform string
}

// ContainerImagesService handles requests for ContainerImage resources on the given Org
type ContainerImagesService struct {
	client *Client
	orgID  string
}

func (r *resource) intoContainerImage() ContainerImage {
	return ContainerImage{
		ID:       r.ID,
		Layers:   r.Attributes.Layers,
		Names:    r.Attributes.Names,
		Platform: r.Attributes.Platform,
	}
}

// GetAll gets all container images for the given org
func (s *ContainerImagesService) GetAll() ([]ContainerImage, error) {
	var images []ContainerImage
	path := fmt.Sprintf("/rest/orgs/%s/container_images", s.orgID)
	params := url.Values{}
	params.Set("version", "2024-01-23~beta")
	resources, err := getMultiResource(s.client, path, params)
	if err != nil {
		return nil, err
	}

	for _, r := range resources {
		images = append(images, r.intoContainerImage())
	}

	return images, nil
}

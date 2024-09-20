package snyk

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Resource is a general resource structure used by the Snyk REST API. This can return many different types of data and is determined by the `ResourceType` field
type resource struct {
	ResourceType string `json:"type"`
	ID           string `json:"id"`
	Attributes   struct {
		GroupID             string         `json:"group_id,omitempty"`
		Name                string         `json:"name,omitempty"`
		DisplayName         string         `json:"displayName,omitempty"`
		Slug                string         `json:"slug,omitempty"`
		Type                string         `json:"type,omitempty"`
		TargetFile          string         `json:"target_file,omitempty"`
		TargetReference     string         `json:"target_reference,omitempty"`
		Origin              string         `json:"origin,omitempty"`
		Created             time.Time      `json:"created,omitempty"` // Should be datetime
		Status              string         `json:"status,omitempty"`
		BusinessCriticality []string       `json:"business_criticality,omitempty"`
		Environment         []string       `json:"environment,omitempty"`
		Lifecycle           []string       `json:"lifecycle,omitempty"`
		Tags                []tag          `json:"tags,omitempty"`
		ReadOnly            bool           `json:"read_only,omitempty"`
		Settings            map[string]any `json:"settings,omitempty"`
		IsPrivate           bool           `json:"isPrivate,omitempty"`
		RemoteURL           string         `json:"remoteUrl,omitempty"`

		// IssueDetails
		IssueType            string        `json:"issueType,omitempty"`
		Title                string        `json:"title,omitempty"`
		Severity             string        `json:"severity,omitempty"`
		CWE                  []string      `json:"cwe,omitempty"`
		Ignored              bool          `json:"ignored,omitempty"`
		Fingerprint          string        `json:"fingerprint,omitempty"`
		FingerprintVersion   string        `json:"fingerprintVersion,omitempty"`
		PrimaryRegion        primaryRegion `json:"primaryRegion,omitempty"`
		PriorityScore        int           `json:"priorityScore,omitempty"`
		PriorityScoreFactors []string      `json:"priorityScoreFactors,omitempty"`
		PrimaryFilePath      string        `json:"primaryFilePath,omitempty"`

		// IssueV2
		EffectiveSeverityLevel string     `json:"effective_severity_level,omitempty"`
		Key                    string     `json:"key,omitempty"`
		CreatedAt              *time.Time `json:"created_at,omitempty"`
		UpdatedAt              *time.Time `json:"updated_at,omitempty"`
		Classes                []Data     `json:"classes,omitempty"`
		Problems               []Data     `json:"problems,omitempty"`
		Resolution             resolution `json:"resolution,omitempty"`

		// ContainerImage
		Layers   []string `json:"layers"`
		Names    []string `json:"names"`
		Platform string   `json:"platform"`
	} `json:"attributes"`
	Meta          meta                    `json:"meta,omitempty"`
	Relationships map[string]Relationship `json:"relationships,omitempty"`
}

type multiResourceResp struct {
	Data  []resource `json:"data"`
	Links links      `json:"links"`
}

type singleResourceResp struct {
	Data  resource `json:"data"`
	Links links    `json:"links"`
}

type meta struct {
	CliMonitoredAt        time.Time `json:"cli_monitored_at,omitempty"` // Should be datetime
	LatestDependencyTotal struct {
		Total     int       `json:"total,omitempty"`
		UpdatedAt time.Time `json:"updated_at,omitempty"`
	} `json:"latest_dependency_total,omitempty"`
	LatestIssueCounts struct {
		Critical  int       `json:"critical,omitempty"`
		High      int       `json:"high,omitempty"`
		Medium    int       `json:"medium,omitempty"`
		Low       int       `json:"low,omitempty"`
		UpdatedAt time.Time `json:"updated_at,omitempty"`
	} `json:"latest_issue_counts,omitempty"`
}

type tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type resolution struct {
	Details    string     `json:"details"`
	ResolvedAt *time.Time `json:"resolved_at"`
	Type       string     `json:"type"`
}

// Data is a general container for Snyk resources
type Data struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Source    string    `json:"source,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type links struct {
	Related string `json:"related"`
	Prev    string `json:"prev"`
	Next    string `json:"next"`
}

// Relationship represents a connections between two or more Snyk resources
type Relationship struct {
	Data  Data  `json:"data"`
	Links links `json:"links"`
}

type primaryRegion struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

func getMultiResource(client *Client, path string, addlParams url.Values) ([]resource, error) {
	var resources []resource
	params := url.Values{}
	if !addlParams.Has("version") {
		params.Set("version", client.APIVersion)
	}
	params.Set("limit", "100")

	if addlParams != nil {
		for k, vSlice := range addlParams {
			for _, v := range vSlice {
				params.Set(k, v)
			}
		}
	}

	apiVersion := params.Get("version")

	urlPath := path

	for {
		resp, err := client.Get(urlPath, params)
		if err != nil {
			return nil, err
		}

		respBody := multiResourceResp{}
		err = json.NewDecoder(resp.Body).Decode(&respBody)
		if err != nil {
			return nil, err
		}

		resources = append(resources, respBody.Data...)

		if respBody.Links.Next == "" || len(respBody.Data) == 0 {
			break
		}

		urlPath = respBody.Links.Next

		// Some versions of the Snyk REST API have "/rest" at the beginning of the "next" URL path... some don't...
		if !strings.HasPrefix(urlPath, "/rest") {
			urlPath = fmt.Sprintf("/rest/%s", urlPath)
		}

		params = nil

		// Some versions of the Snyk REST API include the 'version' param from the original request in the "next" URL path... some don't...
		requestURL, err := getReqURL(urlPath)
		if err != nil {
			return nil, err
		}
		if requestURL.Query().Get("version") == "" {
			params = requestURL.Query()
			params.Set("version", apiVersion)
		}
	}

	return resources, nil
}

func getSingleResource(client *Client, path string, addlParams url.Values) (resource, error) {
	var res resource
	params := url.Values{}
	if !addlParams.Has("version") {
		params.Set("version", client.APIVersion)
	}

	if addlParams != nil {
		for k, vSlice := range addlParams {
			for _, v := range vSlice {
				params.Set(k, v)
			}
		}
	}

	urlPath := path

	resp, err := client.Get(urlPath, params)
	if err != nil {
		return res, err
	}

	respBody := singleResourceResp{}
	err = json.NewDecoder(resp.Body).Decode(&respBody)
	if err != nil {
		return res, err
	}

	return respBody.Data, nil
}

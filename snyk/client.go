package snyk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	baseURL           = "https://api.snyk.io/"
	defaultAPIVersion = "2023-09-14~beta"
	defaultMaxRetries = 6
)

// Client provides methods for working with the Snyk API
type Client struct {
	httpClient *http.Client
	token      string
	APIVersion string
	common     service
	Orgs       *OrgsService
	Users      *UsersService
	Groups     *GroupsService
	maxRetries int
}

type service struct {
	client *Client
}

// NewClient creates a new Snyk API client.
func NewClient(token string) *Client {
	c := &Client{
		httpClient: http.DefaultClient,
		token:      token,
		APIVersion: defaultAPIVersion,
		maxRetries: defaultMaxRetries,
	}

	c.common.client = c

	c.Orgs = (*OrgsService)(&c.common)
	c.Users = (*UsersService)(&c.common)
	c.Groups = (*GroupsService)(&c.common)

	return c
}

// SetMaxRetries sets how many times a failed request will be retried before returning an error
// (default = 6). Requests are retried when the client receives a 429 or 500 response.
// Each retry delay is caculated as `delay = 2^i` where delay is the time to wait in seconds and
// `i` is the current retry iteration. So a `maxRetry` value of 6 would wait a maximum of
// `2^6 = 64 seconds` on its final iteration.
func (c *Client) SetMaxRetries(retries int) {
	c.maxRetries = retries
}

// General function for sending requests to Snyk. The urlPath parameter should not include the domain for the request,
// only the path. The domain will be prepended.
func (c *Client) send(method string, urlPath string, params url.Values, body any) (*http.Response, error) {
	requestURL, err := getReqURL(urlPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		requestURL.RawQuery = params.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("Failed to serialize request body; %s", err.Error())
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, requestURL.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.token)
	req.Header.Set("accept", "*/*")

	if strings.HasPrefix(strings.TrimPrefix(urlPath, "/"), "rest/") {
		req.Header.Set("Content-Type", "application/vnd.api+json")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	retryResponseCodes := []int{429, 500}
	if isInSlice(resp.StatusCode, retryResponseCodes) {
		for i := 0; i <= defaultMaxRetries; i++ {
			retryAfter := resp.Header.Get("Retry-After")
			retryAfterInt, err := strconv.Atoi(retryAfter)

			var interval time.Duration
			if err == nil {
				// The `/v1/groups/GROUP_ID/members` endpoint has a rate limit of 1 request per minute
				// It also seems to accumulate that wait time if multiple requests are made within the timeout
				// https://snyk.docs.apiary.io/#reference/groups/list-members-in-a-group
				log.Printf("Got %d. Retrying in %d seconds.", resp.StatusCode, retryAfterInt+5)
				interval = time.Duration(retryAfterInt + 5)
			} else {
				interval = time.Duration(math.Exp2(float64(i)))
			}
			time.Sleep(interval * time.Second)

			resp, err = c.httpClient.Do(req)
			if !isInSlice(resp.StatusCode, retryResponseCodes) {
				break
			}
		}
	}

	if resp.StatusCode == 502 {
		time.Sleep(30 * time.Second)
		resp, err = c.httpClient.Do(req)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("error: %s", getRespBody(resp))
	}

	return resp, err
}

func getReqURL(urlPath string) (*url.URL, error) {
	requestPath, err := joinURLParts(baseURL, urlPath)
	if err != nil {
		return nil, err
	}

	return url.Parse(requestPath)
}

// Get sends a get request to the Snyk API
func (c *Client) Get(urlPath string, params url.Values) (*http.Response, error) {
	resp, err := c.send(http.MethodGet, urlPath, params, nil)
	return resp, err
}

// Post sends a post request to the Snyk API
func (c *Client) Post(urlPath string, params url.Values, body any) (*http.Response, error) {
	resp, err := c.send(http.MethodPost, urlPath, params, body)
	return resp, err
}

// Put sends a put request to the Snyk API
func (c *Client) Put(urlPath string, body any) (*http.Response, error) {
	resp, err := c.send(http.MethodPut, urlPath, nil, body)
	return resp, err
}

// Patch sends a patch request to the Snyk API
func (c *Client) Patch(urlPath string, params url.Values, body any) (*http.Response, error) {
	resp, err := c.send(http.MethodPatch, urlPath, params, body)
	return resp, err
}

// Delete sends a delete request to the Snyk API
func (c *Client) Delete(urlPath string, params url.Values) (*http.Response, error) {
	resp, err := c.send(http.MethodDelete, urlPath, params, nil)
	return resp, err
}

func getRespBody(resp *http.Response) string {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Could not get reponse body"
	}
	bodyString := string(bodyBytes)
	return fmt.Sprintf("'%d': '%s'", resp.StatusCode, bodyString)
}

// Joins two parts of a URL into a full URL string, preserving the query string since Go doesn't include anything for doing this.
func joinURLParts(base string, suffix string) (string, error) {
	suffixURL, err := url.Parse(suffix)
	if err != nil {
		return "", err
	}

	joined, err := url.JoinPath(base, suffixURL.Path)
	if err != nil {
		return "", err
	}

	joinedURL, err := url.Parse(joined)
	if err != nil {
		return "", err
	}

	joinedURL.RawQuery = suffixURL.RawQuery

	return joinedURL.String(), nil
}

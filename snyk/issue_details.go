package snyk

import (
	"fmt"
	"net/url"
)

// IssueDetails provides additional details about an issue
type IssueDetails struct {
	ID                   string
	Type                 string
	IssueType            string
	Title                string
	Severity             string
	CWE                  []string
	Ignored              bool
	Fingerprint          string
	FingerprintVersion   string
	PrimaryRegion        primaryRegion
	PriorityStore        int
	PriorityScoreFactors []string
	PrimaryFilePath      string
}

func (r *resource) intoIssueDetails() IssueDetails {
	return IssueDetails{
		ID:                   r.ID,
		Type:                 r.ResourceType,
		IssueType:            r.Attributes.IssueType,
		Title:                r.Attributes.Title,
		Severity:             r.Attributes.Severity,
		CWE:                  r.Attributes.CWE,
		Ignored:              r.Attributes.Ignored,
		Fingerprint:          r.Attributes.Fingerprint,
		FingerprintVersion:   r.Attributes.FingerprintVersion,
		PrimaryRegion:        r.Attributes.PrimaryRegion,
		PriorityStore:        r.Attributes.PriorityScore,
		PriorityScoreFactors: r.Attributes.PriorityScoreFactors,
		PrimaryFilePath:      r.Attributes.PrimaryFilePath,
	}
}

// GetDetails provides additional information about an issue
func (i *IssueV2) GetDetails() (IssueDetails, error) {
	var path string
	params := url.Values{}

	switch i.Type {
	case "code":
		path = fmt.Sprintf("rest/orgs/%s/issues/detail/code/%s", i.OrgID, i.Key)
		params.Add("version", "2024-01-24~experimental")
		params.Add("project_id", i.ProjectID)
	default:
		return IssueDetails{}, fmt.Errorf("GetIssueDetails is not yet implemented for issues of type %s", i.Type)
	}

	res, err := getSingleResource(i.client, path, params)
	if err != nil {
		return IssueDetails{}, err
	}

	issueDetails := res.intoIssueDetails()

	return issueDetails, nil
}

// {
//   "type": "code_issue",
//   "id": "6f1b1914-d1b7-4047-841d-84519e8e3edf",
//   "attributes": {
//     "issueType": "code",
//     "title": "Use after free. pChar is used in PC_SimpleReq after it may already have been freed with <unknown>.",
//     "severity": "medium",
//     "cwe": [
//       "CWE-416"
//     ],
//     "ignored": false,
//     "fingerprint": "57664a44.277c621c.7be03776.cc899355.aa2c8a7f.6ba7364b.e2056db8.5b6cf5fb.2178859d.277c621c.c690af74.cc899355.d5421082.98c7c24d.d9bed88e.12762bc3",
//     "fingerprintVersion": "1",
//     "primaryRegion": {
//       "endLine": 3886,
//       "endColumn": 36,
//       "startLine": 3886,
//       "startColumn": 31
//     },
//     "priorityScore": 557,
//     "priorityScoreFactors": [
//       "Found in multiple sources",
//       "Found in a file appearing in multiple code flows",
//       "Has fix examples available"
//     ],
//     "primaryFilePath": "ptload/src/ptldcli.c"
//   }
// }

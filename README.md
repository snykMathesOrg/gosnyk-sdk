# Snyk SDK

Provides a Go SDK for interacting with the Snyk API.

Using the beta version of Snyk V2 API as documented [here](https://apidocs.snyk.io) for most endpoint. There are still many endpoints which are not supported by the new API. In such cases, [these docs]() are used instead.

For simplicity, API requests to **https://app.snyk.io/rest** are using the newer API and requests to **https://app.snyk.io/v1** are using the older API.

# Current Status

The following API resources are currently supported:

- Group
  - Get
  - GetAll
  - AddUserToOrg
- Org
  - Get
  - GetAll
  - UpdateUserRole
  - GetSettings
  - UpdateSettings
- Project
  - Get
  - GetAll
  - Create
  - Delete
  - Deactivate
  - UpdateUserRole
  - GetSettings
  - UpdateSettigs
  - GetIntegrations
  - CloneIntegration
  - ImportProject
- Target
  - Get
  - GetAll
  - GetByRemoteURL
- Issue
  - Get
  - GetAll
  - GetIgnored
  - GetIgnore
  - AddIgnore
  - ReplaceIgnore
  - DeleteIgnore
- ContainerImage
  - Get
  - GetAll

# Planned Functionality

- Reading and creating users

# Examples

## Initialize the Client

```go
package main

import (
    "os"

    "snyk/Application-Security/snyk-sdk/snyk"
)

func main() {
	snykToken := os.Getenv("SNYK_TOKEN")
	client := snyk.NewClient(snykToken)
}

```

## Getting Orgs

```go
orgs, err := client.Orgs.GetAll()

// Or get a single Org by its ID
org, err := client.Orgs.Get("<<uuid>>")
```

## Getting Targets in an Org

```go
org, err := client.Orgs.Get("<<uuid>>")
if err != nil {
    log.Fatal(err)
}

targets, err := org.Targets.GetAll()

// Or get a single Target by its ID
target, err := org.Targets.Get("<<uuid>>")
```

## Getting Projects in an Org

```go
org, err := client.Orgs.Get("<<uuid>>")
if err != nil {
    log.Fatal(err)
}

projects, err := org.Projects.GetAll()

// Or get a single Project by its ID
project, err := org.Projects.Get("<<uuid>>")
```

## Getting Issues in a Project

```go
org, _ := client.Orgs.Get("<<uuid>>")
project, _ := org.Projects.Get("<<uuid>>")

issues, _ := project.Issues.GetAll()
```

# Schema

## Org

```go
type Org struct {
	ID   string
	Name string
	Slug string
}
```

## Target

```go
type Target struct {
	ID          string
	DisplayName string
	Origin      string
	RemoteURL   string
	IsPrivate   bool
}
```

## Project

```go
type Project struct {
	ID                  string
	Name                string
	Type                string
	TargetFile          string
	TargetReference     string
	Origin              string
	Created             string
	Status              string
	BusinessCriticality []string
	Environment         []string
	Lifecycle           []string
	Tags                []tag
	ReadOnly            bool
	Meta                meta
}
```

## Issue

```go
type Issue struct {
	ID            string
	IssueType     string
	PkgName       string
	PkgVersions   []string
	PriorityScore int
	Priority      struct {
		Score   int
		Factors []factor
	}
	IssueData struct {
		ID                    string
		Title                 string
		Severity              string
		URL                   string
		Identifiers           issueIdentifiers
		Credit                []string
		ExploitMaturity       string
		SemVer                map[string][]string
		PublicationTime       time.Time
		DisclosureTime        time.Time
		CVSSv3                string
		CVSSScore             float32
		Language              string
		Patches               []patch
		NearestFixedInVersion string
		IsMaliciousPackage    bool
	}
	IsPatched bool
	IsIgnored bool
	FixInfo   struct {
		IsUpgradable          bool
		IsPinnable            bool
		IsPatchable           bool
		IsFixable             bool
		IsPartiallyFixable    bool
		NearestFixedInVersion string
		FixedIn               []string
	}
	Link struct {
		Paths string
	}
}
```

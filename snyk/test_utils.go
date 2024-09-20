package snyk

import (
	"encoding/json"
	"os"
)

func strToJSON(s string) (map[string]any, error) {
	j := map[string]any{}
	err := json.Unmarshal([]byte(s), &j)
	if err != nil {
		return nil, err
	}
	return j, nil
}

func loadFixture(path string) (map[string]any, error) {
	fileContents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	j, err := strToJSON(string(fileContents))
	if err != nil {
		return nil, err
	}
	return j, nil
}

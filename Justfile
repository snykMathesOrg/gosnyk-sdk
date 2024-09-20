VERSION         := `git describe --tags --dirty`
CURRENT_VERSION := `git describe --tags --abbrev=0`

test:
    go test ./snyk

bob: test
    echo yep

release RELEASE_TYPE: test
    #!/bin/bash
    if [[ {{VERSION}} =~ dirty ]]; then
        echo "Current branch is dirty. Not releasing."
        exit 1
    fi

    if [[ {{RELEASE_TYPE}} =~ ^(major|minor|patch)$ ]]; then
        NEXT_VERSION=$(semver {{CURRENT_VERSION}} -i {{RELEASE_TYPE}})
        CONFIRM=$(read -p "Create {{RELEASE_TYPE}} version v${NEXT_VERSION}? [y/N]: " confirm; echo $confirm)
        if [ "$CONFIRM" = "y" ]; then
            git tag v${NEXT_VERSION}
            git push
            git push --tags
        else
            echo "Aborting"
        fi
    else
        echo "RELEASE_TYPE must be one of 'major', 'minor', or 'patch'. Got {{RELEASE_TYPE}}."
        exit 1
    fi

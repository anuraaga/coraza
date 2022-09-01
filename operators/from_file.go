// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package operators

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

var errEmptyPaths = errors.New("empty paths")

func loadFromFile(path string, paths []fs.FS) ([]byte, error) {
	path = filepath.Clean(path)
	if filepath.IsAbs(path) {
		return os.ReadFile(path)
	}

	if len(paths) == 0 {
		return nil, errEmptyPaths
	}

	// handling files by operators is hard because we must know the paths where we can
	// search, for example, the policy path or the binary path...
	// CRS stores the .data files in the same directory as the directives
	var (
		content []byte
		err     error
	)

	for _, p := range paths {
		content, err = fs.ReadFile(p, path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			} else {
				return nil, err
			}
		}

		return content, nil
	}

	return nil, err
}

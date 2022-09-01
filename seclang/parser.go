// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package seclang

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// maxIncludeRecursion is used to avoid DDOS by including files that include
const maxIncludeRecursion = 100

// Parser provides functions to evaluate (compile) SecLang directives
type Parser struct {
	options      *DirectiveOptions
	currentLine  int
	currentFile  string
	currentDir   fs.FS
	includeCount int
}

// FromFile imports directives from a file
// It will return error if any directive fails to parse
// or the file does not exist.
// If the path contains a *, it will be expanded to all
// files in the directory matching the pattern
func (p *Parser) FromFile(profilePath string) error {
	files := []string{}
	if strings.Contains(profilePath, "*") {
		var err error
		files, err = filepath.Glob(profilePath)
		if err != nil {
			return err
		}
	} else {
		files = append(files, profilePath)
	}
	for _, profilePath := range files {
		profilePath = strings.TrimSpace(profilePath)
		profileBase := filepath.Base(profilePath)
		profileDir := filepath.Dir(profilePath)
		p.currentFile = profilePath
		lastDir := p.currentDir
		var currentDir fs.FS
		if lastDir == nil {
			currentDir = os.DirFS(profileDir)
		} else {
			cd, err := fs.Sub(lastDir, profileDir)
			if err != nil {
				p.options.Waf.Logger.Error(err.Error())
				return err
			}
			currentDir = cd
		}
		p.currentDir = currentDir
		file, err := fs.ReadFile(currentDir, profileBase)
		if err != nil {
			p.options.Waf.Logger.Error(err.Error())
			return err
		}

		err = p.FromString(string(file))
		if err != nil {
			p.options.Waf.Logger.Error(err.Error())
			return err
		}
		// restore the lastDir post processing all includes
		p.currentDir = lastDir
	}
	return nil
}

// FromString imports directives from a string
// It will return error if any directive fails to parse
// or arguments are invalid
func (p *Parser) FromString(data string) error {
	scanner := bufio.NewScanner(strings.NewReader(data))
	var linebuffer = ""
	pattern := regexp.MustCompile(`\\(\s+)?$`)
	inQuotes := false
	for scanner.Scan() {
		p.currentLine++
		line := strings.TrimSpace(scanner.Text())
		if !inQuotes && len(line) > 0 && line[len(line)-1] == '`' {
			inQuotes = true
		} else if inQuotes && len(line) > 0 && line[0] == '`' {
			inQuotes = false
		}
		if inQuotes {
			linebuffer += line + "\n"
		} else {
			linebuffer += line
		}

		// Check if line ends with \
		if !pattern.MatchString(line) && !inQuotes {
			err := p.evaluate(linebuffer)
			if err != nil {
				return err
			}
			linebuffer = ""
		} else if !inQuotes {
			linebuffer = strings.TrimSuffix(linebuffer, "\\")
		}
	}
	return nil
}

func (p *Parser) evaluate(data string) error {
	if data == "" || data[0] == '#' {
		return nil
	}
	// first we get the directive
	spl := strings.SplitN(data, " ", 2)
	opts := ""
	if len(spl) == 2 {
		opts = spl[1]
	}
	p.options.Waf.Logger.Debug("parsing directive %q", data)
	directive := spl[0]

	if len(opts) >= 3 && opts[0] == '"' && opts[len(opts)-1] == '"' {
		opts = strings.Trim(opts, `"`)
	}
	directive = strings.ToLower(directive)
	if directive == "include" {
		// this is a special hardcoded case
		// we cannot add it as a directive type because there are recursion issues
		// note a user might still include another file that includes the original file
		// generating a DDOS attack
		if p.includeCount >= maxIncludeRecursion {
			return fmt.Errorf("cannot include more than %d files", maxIncludeRecursion)
		}
		p.includeCount++
		return p.FromFile(opts)
	}
	d, ok := directivesMap[directive]
	if !ok || d == nil {
		return p.log("Unsupported directive " + directive)
	}

	p.options.Opts = opts
	p.options.Config.Set("last_profile_line", p.currentLine)
	p.options.Config.Set("parser_config_file", p.currentFile)
	if p.currentDir != nil {
		p.options.Config.Set("parser_config_dir", p.currentDir)
	}
	p.options.Config.Set("working_dir", os.DirFS("."))

	return d(p.options)
}

func (p *Parser) log(msg string) error {
	msg = fmt.Sprintf("[Parser] [Line %d] %s", p.currentLine, msg)
	p.options.Waf.Logger.Error("[%d] %s", p.currentLine, msg)
	return errors.New(msg)
}

// SetCurrentDir forces the current directory of the parser to dir
// If FromFile was used, the file directory will be used instead unless
// overwritten by this function
// It is mostly used by operators that consumes relative paths
func (p *Parser) SetCurrentDir(dir string) {
	p.currentDir = os.DirFS(dir)
}

// SetCurrentFS sets the fs.FS to use as the current directory when
// resolving relative paths.
func (p *Parser) SetCurrentFS(dir fs.FS) {
	p.currentDir = dir
}

// NewParser creates a new parser from a WAF instance
// Rules and settings will be inserted into the WAF
// rule container (RuleGroup).
func NewParser(waf *coraza.Waf) *Parser {
	p := &Parser{
		options: &DirectiveOptions{
			Waf:      waf,
			Config:   make(types.Config),
			Datasets: make(map[string][]string),
		},
	}
	return p
}

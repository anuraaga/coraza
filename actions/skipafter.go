// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
)

type skipafterFn struct {
	data string
}

func (a *skipafterFn) Init(r *corazawaf.Rule, data string) error {
	a.data = strings.Trim(data, `"`)
	return nil
}

func (a *skipafterFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	tx.WAF.Logger.Debug("[%s] Starting secmarker %q", tx.ID, a.data)
	tx.SkipAfter = a.data
}

func (a *skipafterFn) Type() types.RuleActionType {
	return types.ActionTypeFlow
}

func skipafter() corazawaf.RuleAction {
	return &skipafterFn{}
}

var (
	_ corazawaf.RuleAction = &skipafterFn{}
	_ ruleActionWrapper    = skipafter
)

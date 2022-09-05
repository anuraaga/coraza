// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	utils "github.com/corazawaf/coraza/v3/internal/strings"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/corazawaf/coraza/v3/types/variables"
)

type ctlFunctionType int

const (
	ctlRemoveTargetByID     ctlFunctionType = iota
	ctlRemoveTargetByTag    ctlFunctionType = iota
	ctlRemoveTargetByMsg    ctlFunctionType = iota
	ctlAuditEngine          ctlFunctionType = iota
	ctlAuditLogParts        ctlFunctionType = iota
	ctlForceRequestBodyVar  ctlFunctionType = iota
	ctlRequestBodyAccess    ctlFunctionType = iota
	ctlRequestBodyLimit     ctlFunctionType = iota
	ctlRuleEngine           ctlFunctionType = iota
	ctlRuleRemoveByID       ctlFunctionType = iota
	ctlRuleRemoveByMsg      ctlFunctionType = iota
	ctlRuleRemoveByTag      ctlFunctionType = iota
	ctlHashEngine           ctlFunctionType = iota
	ctlHashEnforcement      ctlFunctionType = iota
	ctlRequestBodyProcessor ctlFunctionType = iota
	ctlResponseBodyAccess   ctlFunctionType = iota
	ctlResponseBodyLimit    ctlFunctionType = iota
	ctlDebugLogLevel        ctlFunctionType = iota
)

type ctlFn struct {
	action     ctlFunctionType
	value      string
	collection variables.RuleVariable
	colKey     string
	colRx      *regexp.Regexp
}

func (a *ctlFn) Init(r *corazawaf.Rule, data string) error {
	var err error
	a.action, a.value, a.collection, a.colKey, err = a.parseCtl(data)
	if len(a.colKey) > 2 && a.colKey[0] == '/' && a.colKey[len(a.colKey)-1] == '/' {
		a.colRx, err = regexp.Compile(a.colKey[1 : len(a.colKey)-1])
		if err != nil {
			return err
		}
	}
	return err
}

func (a *ctlFn) Evaluate(r *corazawaf.Rule, tx *corazawaf.Transaction) {
	switch a.action {
	case ctlRemoveTargetByID:
		ran, err := a.rangeToInts(tx.WAF.Rules.GetRules(), a.value)
		if err != nil {
			tx.WAF.Logger.Error("[ctl REMOVE_TARGET_BY_ID] invalid range: %s", err.Error())
			return
		}
		for _, id := range ran {
			tx.RemoveRuleTargetByID(id, a.collection, a.colKey)
		}
	case ctlRemoveTargetByTag:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if utils.InSlice(a.value, r.Tags) {
				tx.RemoveRuleTargetByID(r.ID, a.collection, a.colKey)
			}
		}
	case ctlRemoveTargetByMsg:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if r.Msg.String() == a.value {
				tx.RemoveRuleTargetByID(r.ID, a.collection, a.colKey)
			}
		}
	case ctlAuditEngine:
		ae, err := types.ParseAuditEngineStatus(a.value)
		if err != nil {
			tx.WAF.Logger.Error(err.Error())
			return
		}
		tx.AuditEngine = ae
	case ctlAuditLogParts:
		// TODO lets switch it to a string
		tx.AuditLogParts = types.AuditLogParts(a.value)
	case ctlForceRequestBodyVar:
		val := strings.ToLower(a.value)
		tx.WAF.Logger.Debug("[ForceRequestBodyVar] Forcing request body var with CTL to %s", val)
		if val == "on" {
			tx.ForceRequestBodyVariable = true
		} else if val == "off" {
			tx.ForceRequestBodyVariable = false
		}
	case ctlRequestBodyAccess:
		tx.RequestBodyAccess = a.value == "on"
	case ctlRequestBodyLimit:
		limit, _ := strconv.ParseInt(a.value, 10, 64)
		tx.RequestBodyLimit = limit
	case ctlRuleEngine:
		re, err := types.ParseRuleEngineStatus(a.value)
		if err != nil {
			tx.WAF.Logger.Error(err.Error())
		}
		tx.RuleEngine = re
	case ctlRuleRemoveByID:
		id, _ := strconv.Atoi(a.value)
		tx.RemoveRuleByID(id)
	case ctlRuleRemoveByMsg:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if r.Msg.String() == a.value {
				tx.RemoveRuleByID(r.ID)
			}
		}
	case ctlRuleRemoveByTag:
		rules := tx.WAF.Rules.GetRules()
		for _, r := range rules {
			if utils.InSlice(a.value, r.Tags) {
				tx.RemoveRuleByID(r.ID)
			}
		}
	case ctlRequestBodyProcessor:
		tx.Variables.ReqbodyProcessor.Set(strings.ToUpper(a.value))
	case ctlHashEngine:
		// Not supported yet
	case ctlHashEnforcement:
		// Not supported yet
	case ctlDebugLogLevel:
		// lvl, _ := strconv.Atoi(a.Value)
		// TODO
		// We cannot update the log level, it would affect the whole waf instance...
		// tx.WAF.SetLogLevel(lvl)
	}

}

func (a *ctlFn) Type() types.RuleActionType {
	return types.ActionTypeNondisruptive
}

func (a *ctlFn) parseCtl(data string) (ctlFunctionType, string, variables.RuleVariable, string, error) {
	spl1 := strings.SplitN(data, "=", 2)
	if len(spl1) != 2 {
		return ctlRemoveTargetByID, "", 0, "", fmt.Errorf("invalid syntax")
	}
	spl2 := strings.SplitN(spl1[1], ";", 2)
	action := spl1[0]
	value := spl2[0]
	colname := ""
	colkey := ""
	if len(spl2) == 2 {
		spl3 := strings.SplitN(spl2[1], ":", 2)
		if len(spl3) == 2 {
			colname = spl3[0]
			colkey = spl3[1]
		} else {
			colkey = spl3[0]
		}
	}
	collection, _ := variables.Parse(strings.TrimSpace(colname))
	colkey = strings.ToLower(colkey)
	var act ctlFunctionType
	switch action {
	case "auditEngine":
		act = ctlAuditEngine
	case "auditLogParts":
		act = ctlAuditLogParts
	case "forceRequestBodyVariable":
		act = ctlForceRequestBodyVar
	case "requestBodyAccess":
		act = ctlRequestBodyAccess
	case "requestBodyLimit":
		act = ctlRequestBodyLimit
	case "requestBodyProcessor":
		act = ctlRequestBodyProcessor
	case "responseBodyAccess":
		act = ctlResponseBodyAccess
	case "responseBodyLimit":
		act = ctlResponseBodyLimit
	case "ruleEngine":
		act = ctlRuleEngine
	case "ruleRemoveById":
		act = ctlRuleRemoveByID
	case "ruleRemoveByMsg":
		act = ctlRuleRemoveByMsg
	case "ruleRemoveByTag":
		act = ctlRuleRemoveByTag
	case "ruleRemoveTargetById":
		act = ctlRemoveTargetByID
	case "ruleRemoveTargetByMsg":
		act = ctlRemoveTargetByMsg
	case "ruleRemoveTargetByTag":
		act = ctlRemoveTargetByTag
	case "hashEngine":
		act = ctlHashEngine
	case "hashEnforcement":
		act = ctlHashEnforcement
	default:
		return 0, "", 0x00, "", fmt.Errorf("invalid ctl action")
	}
	return act, value, collection, strings.TrimSpace(colkey), nil
}

func (a *ctlFn) rangeToInts(rules []*corazawaf.Rule, input string) ([]int, error) {
	ids := []int{}
	spl := strings.SplitN(input, "-", 2)
	var start, end int
	var err error
	if len(spl) != 2 {
		id, err := strconv.Atoi(input)
		if err != nil {
			return nil, err
		}
		start, end = id, id
	} else {
		start, err = strconv.Atoi(spl[0])
		if err != nil {
			return nil, err
		}
		end, err = strconv.Atoi(spl[1])
		if err != nil {
			return nil, err
		}
	}
	for _, r := range rules {
		if r.ID >= start && r.ID <= end {
			ids = append(ids, r.ID)
		}
	}
	return ids, nil
}

func ctl() corazawaf.RuleAction {
	return &ctlFn{}
}

var (
	_ corazawaf.RuleAction = &ctlFn{}
	_ ruleActionWrapper    = ctl
)

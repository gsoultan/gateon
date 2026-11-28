// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package api

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

func withAIAgentRanges(agent, url string) *gateonv1.GlobalConfig {
	return &gateonv1.GlobalConfig{Waf: &gateonv1.WafConfig{BotManagement: &gateonv1.BotManagementConfig{
		AiAgentRanges: []*gateonv1.AIAgentRangeSource{{Agent: agent, Url: url}},
	}}}
}

// TestAnAIAgentListIsCheckedAtSave is ADR 0108's save half, on the path
// REST, Connect and gRPC share. A list decides which clients pass a route's
// challenge as a crawler, so one fetched over plain http:// lets anyone on
// the path name the crawlers; and a list for an agent the gateway does not
// recognise would be stored and never read.
func TestAnAIAgentListIsCheckedAtSave(t *testing.T) {
	for name, proposed := range map[string]*gateonv1.GlobalConfig{
		"plain http":       withAIAgentRanges("GPTBot", "http://lists.example.com/gptbot.json"),
		"an unknown agent": withAIAgentRanges("GPTbot", "https://openai.com/gptbot.json"),
	} {
		if err := validateGlobalSave(&gateonv1.GlobalConfig{}, proposed); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s saved: %v", name, err)
		}
	}
	if err := validateGlobalSave(&gateonv1.GlobalConfig{},
		withAIAgentRanges("GPTBot", "https://openai.com/gptbot.json")); err != nil {
		t.Errorf("a valid list refused at save: %v", err)
	}
}

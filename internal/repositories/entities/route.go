// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package entities

import (
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type Route struct {
	ID          string   `db:"id"`
	Name        string   `db:"name"`
	Type        string   `db:"type"`
	Entrypoints []string `db:"entrypoints"`
	Rule        string   `db:"rule"`
	Priority    int32    `db:"priority"`
	Middlewares []string `db:"middlewares"`
	ServiceID   string   `db:"service_id"`
	TLSConfig   string   `db:"tls_config"` // JSON string
	Disabled    bool     `db:"disabled"`
}

func (e *Route) ToProto() *gateonv1.Route {
	return &gateonv1.Route{
		Id:          e.ID,
		Name:        e.Name,
		Type:        e.Type,
		Entrypoints: e.Entrypoints,
		Rule:        e.Rule,
		Priority:    e.Priority,
		Middlewares: e.Middlewares,
		ServiceId:   e.ServiceID,
		Disabled:    e.Disabled,
		// TLSConfig would need unmarshaling if we want the full proto
	}
}

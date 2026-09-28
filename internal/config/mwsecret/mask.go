// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mwsecret

import (
	"github.com/gsoultan/gateon/internal/config/storedsecret"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
	"google.golang.org/protobuf/proto"
)

// Mask returns a copy of mw as a caller who may write middlewares reads it:
// every stored secret as Sentinel, a reference as the reference, an unset
// secret as "", each basic-auth user as "name:<Sentinel>" and each API key as
// "key_<Sentinel>_<fingerprint>". Everything else reads as it is.
//
// A copy, always: mw comes from the live registry, and masking it in place
// would erase the secrets from the running gateway on a read.
func Mask(mw *gateonv1.Middleware) *gateonv1.Middleware {
	return masked(mw, false)
}

// MaskForReader returns a copy of mw as a caller who may only read middlewares
// reads it: as Mask, except that a reference and a user list read as Sentinel
// too, and so does every value the headers and rewrite middlewares set,
// whatever the header or parameter is called.
func MaskForReader(mw *gateonv1.Middleware) *gateonv1.Middleware {
	return masked(mw, true)
}

// MaskAll masks a list for a caller who may write middlewares, or only read
// them; nil entries are dropped.
func MaskAll(mws []*gateonv1.Middleware, canWrite bool) []*gateonv1.Middleware {
	out := make([]*gateonv1.Middleware, 0, len(mws))
	for _, mw := range mws {
		if m := masked(mw, !canWrite); m != nil {
			out = append(out, m)
		}
	}
	return out
}

func masked(mw *gateonv1.Middleware, reader bool) *gateonv1.Middleware {
	if mw == nil {
		return nil
	}
	clone, ok := proto.Clone(mw).(*gateonv1.Middleware)
	if !ok || mw.Config == nil {
		return clone
	}
	out := make(map[string]string, len(mw.Config))
	for k, v := range mw.Config {
		switch classify(mw.Type, k) {
		case keyName:
			out[apiKeyMarker(mw.Id, k[len(apiKeyPrefix):])] = v
		case userList:
			out[k] = maskUsers(v, reader)
		case scalar:
			out[k] = maskValue(v, reader)
		default:
			if _, sets := setName(mw.Type, k); sets && reader {
				v = maskValue(v, true)
			}
			out[k] = v
		}
	}
	clone.Config = out
	return clone
}

func maskValue(v string, reader bool) string {
	switch {
	case v == "":
		return ""
	case !reader && storedsecret.IsReference(v):
		return v
	default:
		return Sentinel
	}
}

// maskUsers shows a writer every user's name and none of their passwords, so
// that a user can be kept, renamed away from or removed by name. A value the
// middleware resolves as a whole, or could not read as a list, is one secret.
func maskUsers(v string, reader bool) string {
	if v == "" || reader || isOpaque(v) {
		return maskValue(v, reader)
	}
	users, ok := parseUsers(v)
	if !ok {
		return Sentinel
	}
	for i := range users {
		if users[i].password != "" {
			users[i].password = Sentinel
		}
	}
	return joinUsers(users)
}

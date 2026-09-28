// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package mwsecret

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/gsoultan/gateon/internal/config/storedsecret"
	"github.com/gsoultan/gateon/internal/security/secretmask"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Restore puts back into update every stored secret it keeps, and refuses one
// it cannot keep. stored is the middleware with update's id as it is stored,
// or nil when there is none.
//
// Per secret, the update's value means:
//   - Sentinel: keep the stored value exactly as it is held -- a literal, an
//     encrypted value or a reference. Refused when nothing is stored there, when
//     no stored middleware has this id, when the update changes the
//     middleware's type or kind of authentication, and when it changes where
//     the middleware sends its secrets (storedsecret.ErrMoved).
//   - "": clear it. A secret the middleware cannot run without is then refused
//     by the build check every save makes, which names it.
//   - anything else: replace it.
//
// A basic-auth user keeps the stored password of the stored user with the same
// name, and an API key shown as "key_<Sentinel>_<fingerprint>" the stored key
// with that fingerprint; an element that matches none is refused, named.
// Sentinel anywhere else is refused. Every refusal is returned, joined, and on
// a refusal update is left as it was.
func Restore(update, stored *gateonv1.Middleware) error {
	if update == nil || len(secretmask.Held(update.Config)) == 0 {
		return nil
	}
	if err := keepable(update, stored); err != nil {
		return err
	}
	out := make(map[string]string, len(update.Config))
	var errs []error
	for _, k := range slices.Sorted(maps.Keys(update.Config)) {
		if err := restoreEntry(update, stored.Config, k, out); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	update.Config = out
	return nil
}

// keepable refuses every placeholder of an update that cannot keep a stored
// secret at all, naming them.
func keepable(update, stored *gateonv1.Middleware) error {
	held := strings.Join(secretmask.Held(update.Config), ", ")
	switch {
	case stored == nil:
		return fmt.Errorf("%s: %w", held, ErrNewMiddleware)
	case identity(update) != identity(stored):
		return fmt.Errorf("%s: %w (stored as %q, now %q)", held, ErrTypeChanged, identity(stored), identity(update))
	}
	if key := destinationKey(update); key != "" &&
		strings.TrimSpace(update.Config[key]) != strings.TrimSpace(stored.Config[key]) {
		return fmt.Errorf("%s: %w (%s changed)", held, storedsecret.ErrMoved, key)
	}
	return nil
}

func restoreEntry(update *gateonv1.Middleware, stored map[string]string, k string, out map[string]string) error {
	v := update.Config[k]
	switch kd := classify(update.Type, k); {
	case strings.Contains(k, Sentinel):
		return restoreAPIKey(update.Id, stored, apiKeyEntry{marker: k, label: v}, out)
	case !strings.Contains(v, Sentinel):
		// Only a kept API key can already be there: the literal key it stands
		// for, sent beside its marker, would give it two tenants.
		if hasKey(out, k) {
			return fmt.Errorf("%s: the same API key is sent and kept", k)
		}
		out[k] = v
		return nil
	case kd == userList:
		return restoreUsers(stored, k, v, out)
	case kd == scalar:
		return restoreScalar(stored, k, v, out)
	default:
		return fmt.Errorf("%s: %w", k, ErrNotASecret)
	}
}

func restoreScalar(stored map[string]string, k, v string, out map[string]string) error {
	kept := stored[k]
	switch {
	case v != Sentinel:
		return fmt.Errorf("%s: %w", k, storedsecret.ErrPartialPlaceholder)
	case kept == "":
		return fmt.Errorf("%s: %w", k, storedsecret.ErrNothingStored)
	}
	out[k] = kept
	return nil
}

// apiKeyEntry is an API key as an update sends it back: the marker it was
// shown as, and the tenant label, which the update may have changed.
type apiKeyEntry struct{ marker, label string }

// restoreAPIKey keeps the stored API key a marker's fingerprint names, under
// the tenant label the update gives it.
func restoreAPIKey(middlewareID string, stored map[string]string, e apiKeyEntry, out map[string]string) error {
	fp, ok := markerFingerprint(e.marker)
	if !ok || strings.Contains(e.label, Sentinel) {
		return fmt.Errorf("%s: %w", e.marker, storedsecret.ErrPartialPlaceholder)
	}
	apiKey, found := storedAPIKey(middlewareID, stored, fp)
	switch {
	case !found:
		return fmt.Errorf("API key %s (tenant %q): no stored API key has this fingerprint -- it was removed "+
			"or replaced since this was read; enter the key again", fp, e.label)
	case hasKey(out, apiKeyPrefix+apiKey):
		return fmt.Errorf("API key %s (tenant %q): the same stored API key is kept twice", fp, e.label)
	}
	out[apiKeyPrefix+apiKey] = e.label
	return nil
}

func hasKey(m map[string]string, k string) bool {
	_, ok := m[k]
	return ok
}

// restoreUsers keeps each user's stored password by the user's name.
func restoreUsers(stored map[string]string, k, v string, out map[string]string) error {
	if v == Sentinel {
		return restoreScalar(stored, k, v, out)
	}
	users, ok := parseUsers(v)
	if !ok {
		return fmt.Errorf("%s: %w", k, storedsecret.ErrPartialPlaceholder)
	}
	byName := usersByName(stored[k])
	var errs []error
	for i, u := range users {
		kept, found := byName[u.name]
		switch {
		case strings.Contains(u.name, Sentinel) || (u.password != Sentinel && strings.Contains(u.password, Sentinel)):
			errs = append(errs, fmt.Errorf("%s: user %q: %w", k, u.name, storedsecret.ErrPartialPlaceholder))
		case u.password != Sentinel:
		case !found || kept == "":
			errs = append(errs, fmt.Errorf("%s: user %q: no stored user has this name, so there is no stored "+
				"password to keep -- a renamed user needs its password entered again", k, u.name))
		default:
			users[i].password = kept
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	out[k] = joinUsers(users)
	return nil
}

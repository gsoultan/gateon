// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package storedsecret

import (
	"errors"
	"fmt"
	"strings"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// Restore puts back into update every stored credential the update keeps, and
// refuses one it cannot keep. stored is the configuration in force.
//
// Per credential field, the update's value means:
//   - Sentinel: keep the stored value exactly as it is held -- a literal, an
//     encrypted value or a reference. Refused when nothing is stored, and when
//     the same update moves the secret's destination (ErrMoved).
//   - a connection URL with Sentinel as its password: keep the stored URL, if
//     the rest of it is unchanged; refused otherwise, for the same reason.
//   - "": clear it -- except a Required key, which is kept. The gateway cannot
//     run without its session key, audit key or proof-of-work key, and an empty
//     one is what a client that did not send the field sends.
//   - anything else: replace it.
//
// A list element's secrets are kept from the stored element with the same id,
// and from no other: an element that asks to keep a secret and has no id, or
// an id no stored element has, or one two stored elements share, is refused
// with its name. Every refusal is returned, joined; update may then be partly
// restored and must not be stored.
func Restore(update, stored *gateonv1.GlobalConfig) error {
	if update == nil {
		return nil
	}
	var errs []error
	for _, f := range fields {
		if err := restoreField(f, update, stored); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.Name, err))
		}
	}
	for _, l := range lists {
		errs = append(errs, restoreList(l, update, stored)...)
	}
	return errors.Join(errs...)
}

func restoreField(f Field, update, stored *gateonv1.GlobalConfig) error {
	p := f.Ptr(update)
	if p == nil {
		return nil
	}
	kept := ""
	if s := f.Ptr(stored); s != nil {
		kept = *s
	}
	switch {
	case *p == "" && f.Required:
		*p = kept
		return nil
	case !strings.Contains(*p, Sentinel):
		return nil
	case kept == "":
		return ErrNothingStored
	case *p != Sentinel:
		return keepURL(f, p, kept)
	case f.Destination != nil && f.Destination(update) != f.Destination(stored):
		return ErrMoved
	}
	*p = kept
	return nil
}

// keepURL keeps a stored connection URL for an update that sends it back as
// Mask showed it: with only its password replaced by Sentinel. Anything else
// that merely contains Sentinel is refused -- a URL whose host, user or
// database changed would otherwise carry the stored password to a server the
// caller chose.
func keepURL(f Field, p *string, kept string) error {
	shown := masked(kept, true)
	switch {
	case !f.URL:
		return ErrPartialPlaceholder
	case shown == *p:
		*p = kept
		return nil
	case strings.Contains(shown, Sentinel):
		return ErrMoved
	default:
		return ErrPartialPlaceholder
	}
}

func restoreList(l List, update, stored *gateonv1.GlobalConfig) []error {
	var byID map[string][]Element
	var errs []error
	for i, e := range l.Elements(update) {
		if !keepsASecret(e) {
			continue
		}
		if byID == nil {
			byID = indexByID(l.Elements(stored))
		}
		if err := restoreElement(e, byID[*e.ID]); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", describe(l, i, e), err))
		}
	}
	return errs
}

func restoreElement(e Element, matches []Element) error {
	switch {
	case *e.ID == "":
		return errors.New("it has no id, so no stored element can be matched to it; enter its secrets again")
	case len(matches) == 0:
		return errors.New("no stored element has this id, so there is no stored secret to keep; enter its secrets again")
	case len(matches) > 1:
		return fmt.Errorf("%d stored elements share this id, so which secret to keep is ambiguous; enter its secrets again",
			len(matches))
	case matches[0].Destination != e.Destination:
		return ErrMoved
	}
	var errs []error
	for j, s := range e.Secrets {
		if !strings.Contains(*s.Ptr, Sentinel) {
			continue
		}
		kept := *matches[0].Secrets[j].Ptr
		switch {
		case *s.Ptr != Sentinel:
			errs = append(errs, fmt.Errorf("%s: %w", s.Name, ErrPartialPlaceholder))
		case kept == "":
			errs = append(errs, fmt.Errorf("%s: %w", s.Name, ErrNothingStored))
		default:
			*s.Ptr = kept
		}
	}
	return errors.Join(errs...)
}

func keepsASecret(e Element) bool {
	for _, s := range e.Secrets {
		if strings.Contains(*s.Ptr, Sentinel) {
			return true
		}
	}
	return false
}

func indexByID(elements []Element) map[string][]Element {
	byID := make(map[string][]Element, len(elements))
	for _, e := range elements {
		if *e.ID != "" {
			byID[*e.ID] = append(byID[*e.ID], e)
		}
	}
	return byID
}

// describe names a list element for a refusal: by id and name, which is how
// the operator knows it, with its position only when it has no id.
func describe(l List, position int, e Element) string {
	if *e.ID == "" {
		return fmt.Sprintf("%s[%d] (name %q)", l.Name, position, e.Name)
	}
	return fmt.Sprintf("%s[id %q, name %q]", l.Name, *e.ID, e.Name)
}

// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package globalbound

import (
	"google.golang.org/protobuf/reflect/protoreflect"

	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

// triple walks the stored configuration, the writer's view of it and the
// proposed one in step. An absent section reads as its zero value in each, so
// a section sent back empty where none was stored is not a change.
type triple struct {
	stored, view, proposed protoreflect.Message
}

func newTriple(ch Change) (triple, bool) {
	if ch.Proposed == nil {
		return triple{}, false
	}
	stored := ch.Stored
	if stored == nil {
		stored = &gateonv1.GlobalConfig{}
	}
	view := ch.View
	if view == nil {
		view = stored
	}
	return triple{stored: stored.ProtoReflect(), view: view.ProtoReflect(), proposed: ch.Proposed.ProtoReflect()}, true
}

func (t triple) child(fd protoreflect.FieldDescriptor) triple {
	return triple{
		stored:   t.stored.Get(fd).Message(),
		view:     t.view.Get(fd).Message(),
		proposed: t.proposed.Get(fd).Message(),
	}
}

// changed reports whether the proposed value of fd differs from both the
// stored value and the writer's view of it.
func (t triple) changed(fd protoreflect.FieldDescriptor) bool {
	p := t.proposed.Get(fd)
	return !p.Equal(t.stored.Get(fd)) && !p.Equal(t.view.Get(fd))
}

type action uint8

const (
	skip action = iota
	descend
	compare
)

// pickFunc decides what to do with fd, and whether the fields under it are
// inside a selected subtree.
type pickFunc func(fd protoreflect.FieldDescriptor, inherited bool) (action, bool)

// boundaryPick selects every Boundary field, the whole subtree of a
// message-typed one, and an unclassified field as if it were Boundary.
func boundaryPick(fd protoreflect.FieldDescriptor, inherited bool) (action, bool) {
	if !inherited {
		switch effective(fd) {
		case Operational:
			return skip, false
		case Section:
			return descend, false
		}
	}
	if singularMessage(fd) {
		return descend, true
	}
	return compare, true
}

// recordPick selects the settings that decide what is recorded.
func recordPick(fd protoreflect.FieldDescriptor, inherited bool) (action, bool) {
	in := inherited || recordFields[fd.FullName()]
	switch {
	case singularMessage(fd):
		return descend, in
	case in:
		return compare, true
	default:
		return skip, false
	}
}

// differ collects the changed fields a pickFunc selects.
type differ struct {
	pick    pickFunc
	changes []FieldChange
}

func (d *differ) walk(t triple, prefix string, inherited bool) {
	fields := t.proposed.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		act, in := d.pick(fd, inherited)
		path := string(fd.Name())
		if prefix != "" {
			path = prefix + "." + path
		}
		switch act {
		case descend:
			d.walk(t.child(fd), path, in)
		case compare:
			if t.changed(fd) {
				d.changes = append(d.changes, FieldChange{
					Path: path, From: t.stored.Get(fd), To: t.proposed.Get(fd), Field: fd,
				})
			}
		case skip:
		}
	}
}

func (d *differ) paths() []string {
	out := make([]string, 0, len(d.changes))
	for _, c := range d.changes {
		out = append(out, c.Path)
	}
	return out
}

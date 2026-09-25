// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package request

import (
	"reflect"
	"testing"
)

// TestResetClearsEveryField: RequestState is pooled, and a field Reset misses
// is carried into the next request that draws the same state -- another
// client's route, IsManagement, reputation identity or fingerprints, or a
// RecordedRequest that makes the next request's statistics go unrecorded. Set
// every field, reset, and require each to be zero, so a field added later
// without a line in Reset fails here rather than in production.
func TestResetClearsEveryField(t *testing.T) {
	rs := &RequestState{}
	v := reflect.ValueOf(rs).Elem()
	for i := range v.NumField() {
		setNonZero(t, v.Type().Field(i).Name, v.Field(i))
	}
	rs.Reset()
	for i := range v.NumField() {
		if !v.Field(i).IsZero() {
			t.Errorf("Reset left %s = %v", v.Type().Field(i).Name, v.Field(i))
		}
	}
}

func setNonZero(t *testing.T, name string, f reflect.Value) {
	t.Helper()
	switch f.Kind() {
	case reflect.String:
		f.SetString("x")
	case reflect.Bool:
		f.SetBool(true)
	case reflect.Int, reflect.Int64:
		f.SetInt(1)
	case reflect.Float64:
		f.SetFloat(1)
	case reflect.Slice:
		f.Set(reflect.MakeSlice(f.Type(), 1, 1))
	case reflect.Pointer:
		f.Set(reflect.New(f.Type().Elem()))
	case reflect.Interface:
		f.Set(reflect.ValueOf("x"))
	default:
		t.Fatalf("field %s has kind %s; teach setNonZero to fill it", name, f.Kind())
	}
}

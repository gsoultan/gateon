// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import (
	"strconv"
	"strings"
)

// Version is a release version, MAJOR.MINOR.PATCH. A pre-release, a snapshot
// ("1.8.2-next") and a development build are not release versions and do not
// parse: they cannot be ordered against a release with any confidence.
type Version struct {
	Major, Minor, Patch int
}

// maxVersionPart bounds each number of a version. A release list is remote
// input; "1.99999999999999999999.0" must not overflow into a small number.
const maxVersionPart = 999_999

// ParseVersion reads "1.8.3" or "v1.8.3". It reports false for anything else.
func ParseVersion(s string) (Version, bool) {
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	var nums [3]int
	for i, p := range parts {
		n, ok := versionPart(p)
		if !ok {
			return Version{}, false
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2]}, true
}

// versionPart reads one number of a version: digits only, no sign, no
// leading zero, at most maxVersionPart.
func versionPart(p string) (int, bool) {
	if p == "" || len(p) > 6 || (len(p) > 1 && p[0] == '0') {
		return 0, false
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(p)
	if err != nil || n > maxVersionPart {
		return 0, false
	}
	return n, true
}

// String is the version without a leading "v", as release artifacts name it.
func (v Version) String() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// Newer reports whether v is a later release than other.
func (v Version) Newer(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor > other.Minor
	}
	return v.Patch > other.Patch
}

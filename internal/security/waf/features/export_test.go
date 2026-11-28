// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package features

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExportLabelsCapsAndDropsDoubtfulCleanRows(t *testing.T) {
	attacks := writeFile(t, "attacks.jsonl", `# a comment, as gwaf's corpus files have
{"method":"GET","target":"/items","args":{"id":"1' UNION SELECT password FROM users--"}}
{"method":"GET","target":"/items","args":{"id":"1 OR 1=1"}}
`)
	var clean strings.Builder
	for range 5 {
		clean.WriteString(`{"method":"GET","target":"/v1/routes?page=1","headers":{"User-Agent":"Mozilla/5.0"}}` + "\n")
	}
	// An attack in the clean corpus, as an Audit Only route forwards one.
	clean.WriteString(`{"method":"GET","target":"/search","args":{"q":"<script>alert(document.cookie)</script>"}}` + "\n")
	cleanPath := writeFile(t, "clean.jsonl", clean.String())

	var out, errOut bytes.Buffer
	code := ExportCLI([]string{"--attacks", attacks, "--clean", cleanPath, "--per-template", "2"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	records, err := csv.NewReader(&out).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0][len(records[0])-1]; got != LabelColumn || len(records[0]) != len(Columns)+1 {
		t.Fatalf("header = %v", records[0])
	}
	labels := map[string]int{}
	for _, r := range records[1:] {
		labels[r[len(r)-1]]++
	}
	if labels[LabelAttack] != 2 || labels[LabelClean] != 2 {
		t.Fatalf("labels = %v, want 2 attack and 2 clean (3 repeats and 1 doubtful left out)", labels)
	}
	if !strings.Contains(errOut.String(), "3 repeats") || !strings.Contains(errOut.String(), "1 clean requests") {
		t.Fatalf("report = %q", errOut.String())
	}
}

func TestExportNeedsBothAnswers(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := ExportCLI([]string{"--clean", "x"}, &out, &errOut); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestExportNamesTheLineItCannotRead(t *testing.T) {
	bad := writeFile(t, "bad.jsonl", "{\"target\":\"/a\"}\nnot json\n")
	ok := writeFile(t, "ok.jsonl", "{\"target\":\"/a\"}\n")
	var out, errOut bytes.Buffer
	if code := ExportCLI([]string{"--attacks", bad, "--clean", ok}, &out, &errOut); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errOut.String(), "line 2") {
		t.Fatalf("error = %q", errOut.String())
	}
}

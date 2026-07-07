package github

import (
	"strconv"
	"strings"

	"github.com/argusappsec/argus/pkg/codehost"
)

// parseHunks extracts the head-side line ranges from a GitHub unified-diff
// patch string. Only the hunk headers matter for inline placement:
//
//	@@ -<oldStart>,<oldLines> +<newStart>,<newLines> @@ optional context
//
// The "+<newStart>,<newLines>" half locates the change on the head (RIGHT)
// side, which is where inline comments attach. A missing ",<newLines>" means a
// single line. A patch with no headers (binary file, GitHub omits the patch)
// yields no hunks.
func parseHunks(patch string) []codehost.Hunk {
	if patch == "" {
		return nil
	}
	var hunks []codehost.Hunk
	for line := range strings.SplitSeq(patch, "\n") {
		if !strings.HasPrefix(line, "@@") {
			continue
		}
		h, ok := parseHunkHeader(line)
		if ok {
			hunks = append(hunks, h)
		}
	}
	return hunks
}

// parseHunkHeader parses the "+newStart,newLines" segment of a hunk header.
func parseHunkHeader(header string) (codehost.Hunk, bool) {
	// Isolate the "@@ ... @@" span and find the "+" segment within it.
	end := strings.Index(header[2:], "@@")
	if end < 0 {
		return codehost.Hunk{}, false
	}
	span := header[2 : 2+end]
	for field := range strings.FieldsSeq(span) {
		if !strings.HasPrefix(field, "+") {
			continue
		}
		start, lines, ok := parseRange(strings.TrimPrefix(field, "+"))
		if !ok {
			return codehost.Hunk{}, false
		}
		return codehost.Hunk{NewStart: start, NewLines: lines}, true
	}
	return codehost.Hunk{}, false
}

// parseRange parses "start" or "start,lines". A bare "start" means one line.
func parseRange(s string) (start, lines int, ok bool) {
	startStr, linesStr, hasComma := strings.Cut(s, ",")
	start, err := strconv.Atoi(startStr)
	if err != nil {
		return 0, 0, false
	}
	lines = 1
	if hasComma {
		lines, err = strconv.Atoi(linesStr)
		if err != nil {
			return 0, 0, false
		}
	}
	return start, lines, true
}

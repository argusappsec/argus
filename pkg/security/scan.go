package security

import (
	"context"
	"errors"

	"github.com/argusappsec/argus/pkg/session"
)

// scanner is what every scanner Tool shares: the Tool name it answers to, the
// binary it runs, the Session its target resolves against and the Runner it
// shells out through. Embedding it gives a Tool its Name and its Schema, which
// are the same shape for every scanner, and scan, the shape of its Execute.
type scanner struct {
	name   string // the Tool name, as the Catalog Entry's Tool
	binary string // names the run's scratch directory and its errors
	sess   *session.Session
	runner Runner
}

func (s scanner) Name() string { return s.name }

// Schema is every scanner's: one optional target path.
func (s scanner) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": targetSchemaProperty(),
		},
	}
}

// reportFile is the scratch file a binary that writes its report to a file is
// told to write it to (see runForReport).
const reportFile = "report.json"

// runFunc is a Tool's own part of a scan: run its binary over root from the
// scratch directory sc, and return what the binary produced for parseFunc to
// read. It writes any Argus-owned config into sc first.
type runFunc func(ctx context.Context, sc *scratch, root string) ([]byte, error)

// parseFunc reads what a run produced into a Report. target is the directory
// scanned; files reads the checkout it belongs to, for suppression markers.
// The caller owns files and closes it.
type parseFunc func(body []byte, target string, files *checkoutFiles) (Report, error)

// nothingToScan is what a runFunc returns when the binary found nothing it
// could scan under the target (zizmor over a tree with no workflows): a clean
// answer, carrying any warnings the binary logged, with no report to parse.
type nothingToScan struct{ logs []string }

func (nothingToScan) Error() string { return "nothing to scan" }

// scan is every scanner Tool's Execute: resolve the target, give the run a
// scratch directory of its own and remove it afterwards, run the binary, and
// parse what it produced over the checkout the target belongs to. A Tool
// supplies only how to run its binary and how to read its report.
func (s scanner) scan(ctx context.Context, args map[string]any, run runFunc, parse parseFunc) (string, error) {
	root, err := scanTarget(s.sess, args)
	if err != nil {
		return "", err
	}
	sc, err := newScratch(s.binary)
	if err != nil {
		return "", err
	}
	defer sc.remove()

	body, err := run(ctx, sc, root)
	var clean nothingToScan
	if errors.As(err, &clean) {
		return Report{Scanner: s.binary, Errors: clean.logs}.encode()
	}
	if err != nil {
		return "", err
	}
	files := openCheckout(s.sess, root)
	defer files.close()
	rep, err := parse(body, root, files)
	if err != nil {
		return "", err
	}
	return rep.encode()
}

// runForReport runs the binary from sc with env on top of the scratch
// allow-list, and reads back the report it wrote to reportFile, which args
// must name (see the package-level runForReport).
func (s scanner) runForReport(ctx context.Context, sc *scratch, env []string, args ...string) ([]byte, error) {
	return runForReport(ctx, s.runner, s.binary, sc.command(env, args...), sc.file(reportFile))
}

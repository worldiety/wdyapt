package repo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/worldiety/wdyapt/internal/debian"
	"github.com/worldiety/wdyapt/internal/openpgp"
	"github.com/worldiety/wdyapt/internal/store"
)

// Rename is a rename that a run still owes.
type Rename struct{ From, To string }

// Pending is a run that was aborted during switching: its temporary files
// are still there, and its signed InRelease references lists that exist
// either already under the final name or still under the temporary one.
type Pending struct {
	Run     string
	Renames []Rename
}

// FindPending looks under dists/<suite>/ for an aborted run whose temporary
// InRelease is trusted by ring and which can be completed with the other
// temporary files of the same run. nil if there is none. It changes
// nothing.
func FindPending(ctx context.Context, st store.Reader, suite string, ring *openpgp.Keyring) (*Pending, error) {
	dist := "dists/" + suite + "/"
	entries, err := st.ReadDir(ctx, strings.TrimSuffix(dist, "/"))
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, store.ErrNoListing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var runs []string
	for _, e := range entries {
		if final, run, ok := store.SplitTemp(e.Name()); ok && final == "InRelease" {
			runs = append(runs, run)
		}
	}
	slices.Sort(runs)
	for _, run := range runs {
		if p, err := pendingRun(ctx, st, dist, run, ring); err == nil {
			return p, nil
		}
	}
	return nil, nil
}

func pendingRun(ctx context.Context, st store.Reader, dist, run string, ring *openpgp.Keyring) (*Pending, error) {
	tmp := func(name string) string { return store.TempName(dist+name, run) }
	inRelease, err := store.ReadLimited(ctx, st, tmp("InRelease"), maxRelease)
	if err != nil {
		return nil, err
	}
	text, _, err := ring.VerifyCleartext(inRelease)
	if err != nil {
		return nil, err
	}
	p, err := debian.ParseOne(string(text))
	if err != nil {
		return nil, err
	}
	pending := &Pending{Run: run}
	var lists []Rename
	for _, line := range debian.Lines(p.Get("SHA256")) {
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("broken line")
		}
		name, err := store.Clean(f[2])
		if err != nil {
			return nil, err
		}
		final, err := store.ReadLimited(ctx, st, dist+name, maxList)
		if err == nil && sumHex("SHA256", final) == f[0] {
			continue
		}
		data, err := store.ReadLimited(ctx, st, tmp(name), maxList)
		if err != nil || sumHex("SHA256", data) != f[0] {
			return nil, fmt.Errorf("%s matches neither", name)
		}
		lists = append(lists, Rename{From: tmp(name), To: dist + name})
	}
	// Packages.gz before Packages, the way publish switches.
	slices.SortFunc(lists, func(a, b Rename) int {
		ka, kb := strings.TrimSuffix(a.To, ".gz"), strings.TrimSuffix(b.To, ".gz")
		if ka != kb {
			return strings.Compare(ka, kb)
		}
		return -strings.Compare(a.To, b.To)
	})
	pending.Renames = lists
	if data, err := store.ReadLimited(ctx, st, tmp("Release"), maxRelease); err == nil {
		if !bytes.Equal(data, text) {
			return nil, fmt.Errorf("Release differs")
		}
		pending.Renames = append(pending.Renames, Rename{From: tmp("Release"), To: dist + "Release"})
	}
	if sig, err := store.ReadLimited(ctx, st, tmp("Release.gpg"), maxRelease); err == nil {
		if _, err := ring.VerifyDetached(text, sig); err != nil {
			return nil, err
		}
		pending.Renames = append(pending.Renames, Rename{From: tmp("Release.gpg"), To: dist + "Release.gpg"})
	}
	pending.Renames = append(pending.Renames, Rename{From: tmp("InRelease"), To: dist + "InRelease"})
	return pending, nil
}

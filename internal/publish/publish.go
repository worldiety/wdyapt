// Package publish carries out a publication: lock, read and verify the
// state, merge, sign, upload and switch. It only knows store.Store and
// therefore works the same for SFTP and directories.
package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/worldiety/wdyapt/internal/openpgp"
	"github.com/worldiety/wdyapt/internal/repo"
	"github.com/worldiety/wdyapt/internal/store"
)

// ErrBusy reports a lock held by another run, or a suite that changed
// during the run; another run may succeed.
var ErrBusy = errors.New("temporary conflict")

// Input is everything a publication needs.
type Input struct {
	Suite     string
	Component string
	Packages  []*repo.Package
	// Signers sign the new Release; Keyring verifies the existing state and
	// contains the public parts of the Signers.
	Signers []*openpgp.Entity
	Keyring *openpgp.Keyring

	Create                               bool
	Architectures                        []string
	Origin, Label, Codename, Description string
	Date                                 time.Time

	DryRun      bool
	OutDir      string
	WaitForLock time.Duration
	BreakLock   bool

	// Lock describes this run in the lock file.
	Lock LockInfo

	Say  func(format string, args ...any)
	Warn func(format string, args ...any)
	// Now returns the time of the signatures; without it time.Now applies.
	Now func() time.Time
}

// LockInfo is written to the lock file; never secrets.
type LockInfo struct {
	Host    string    `json:"host"`
	User    string    `json:"user"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	Version string    `json:"version"`
	Suite   string    `json:"suite"`
}

// Result summarizes a publication.
type Result struct {
	Suite         string     `json:"suite"`
	DryRun        bool       `json:"dry_run"`
	Changed       bool       `json:"changed"`
	Added         []repo.Ref `json:"added"`
	Unchanged     []repo.Ref `json:"unchanged"`
	Uploaded      []string   `json:"uploaded"`
	UploadedBytes int64      `json:"uploaded_bytes"`
	Reused        []string   `json:"reused"`
	Indices       []string   `json:"indices"`
	Date          string     `json:"date,omitempty"`
	Signatures    []string   `json:"signatures"`
	Warnings      []string   `json:"warnings"`
	// Release is the new Release, for --dry-run and --out.
	Release string `json:"-"`
}

func (in *Input) say(format string, args ...any) {
	if in.Say != nil {
		in.Say(format, args...)
	}
}

func (in *Input) warn(res *Result, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	res.Warnings = append(res.Warnings, msg)
	if in.Warn != nil {
		in.Warn("%s", msg)
	}
}

// Run publishes in.Packages into the suite on st:
//
//  1. Create the lock .wdyapt.lock exclusively (taken: wait or ErrBusy).
//  2. Read and verify the state of the suite; complete our own run that was
//     aborted during switching if its signed state matches.
//  3. Merge; nothing to add means nothing to write.
//  4. Sign the Release (InRelease, Release.gpg) and verify it.
//  5. Upload pool files as temporary files, check the size, rename.
//  6. Upload lists and Release files as temporary files.
//  7. Check that the suite is unchanged, else ErrBusy.
//  8. Switch: lists, Release, Release.gpg, InRelease last.
//
// It never deletes a published package and never removes an entry
// (R-DEC-NO-DELETION); a final name never holds a partial file
// (R-DEC-ATOMIC-PUBLISHING); the lock and a second read keep concurrent runs
// apart (R-DEC-LOCK-AND-CONFLICT-DETECTION).
func Run(ctx context.Context, st store.Store, in Input) (res *Result, err error) {
	res = &Result{Suite: in.Suite, DryRun: in.DryRun, Added: []repo.Ref{}, Unchanged: []repo.Ref{}, Uploaded: []string{}, Reused: []string{}, Indices: []string{}, Signatures: []string{}, Warnings: []string{}}
	if err := repo.ValidSuite(in.Suite); err != nil {
		return nil, err
	}
	if len(in.Signers) == 0 {
		return nil, errors.New("no signing key")
	}

	// Root of the repository.
	if _, err := st.Stat(ctx, "."); errors.Is(err, fs.ErrNotExist) {
		if !in.Create {
			return nil, fmt.Errorf("%s does not exist; check --remote, or give --create to create the repository", st.Describe())
		}
		if in.DryRun {
			in.say("Would create %s", st.Describe())
		} else if err := st.MkdirAll(ctx, "."); err != nil {
			return nil, fmt.Errorf("creating %s: %w", st.Describe(), err)
		}
	} else if err != nil {
		return nil, err
	}

	// 1. Lock. A dry run writes nothing, not even a lock.
	locked := false
	if _, err := st.Stat(ctx, "."); err == nil && !in.DryRun {
		if err := lock(ctx, st, &in); err != nil {
			return nil, err
		}
		locked = true
	}
	defer func() {
		if !locked {
			return
		}
		// The lock should go away even after an abort.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if rerr := st.Remove(cctx, repo.LockFile); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("removing the lock %s: %w", repo.LockFile, rerr))
		}
	}()

	// 2. Read and verify the state.
	state, err := readState(ctx, st, &in)
	if err != nil {
		return nil, err
	}
	known, err := otherSuites(ctx, st, &in, res)
	if err != nil {
		return nil, err
	}

	// 3. Merge.
	plan, err := repo.Merge(state, in.Packages, repo.MergeOptions{
		Component: in.Component, Create: in.Create, Architectures: in.Architectures,
		Origin: in.Origin, Label: in.Label, Codename: in.Codename, Description: in.Description,
		Date: in.Date, Known: known,
		Existing: func(name string) (*repo.PoolRef, error) {
			info, err := st.Stat(ctx, name)
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			in.say("Checking %s, which no suite names (%s)", name, humanSize(info.Size()))
			sum, size, err := repo.HashFile(ctx, st, name)
			if err != nil {
				return nil, err
			}
			return &repo.PoolRef{Size: size, SHA256: sum}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	for _, w := range plan.Warnings {
		in.warn(res, "%s", w)
	}
	res.Added, res.Unchanged, res.Reused = append(res.Added, plan.Added...), append(res.Unchanged, plan.Unchanged...), append(res.Reused, plan.Reused...)
	for _, u := range res.Unchanged {
		in.say("%s %s for %s is already published, unchanged", u.Package, u.Version, u.Architecture)
	}
	if !plan.Changed() {
		in.say("Nothing to add to suite %s", in.Suite)
		return res, nil
	}
	res.Changed = true
	res.Date = repo.FormatDate(plan.Date)
	for _, f := range plan.Indices {
		res.Indices = append(res.Indices, f.Path)
	}
	res.Release = string(plan.Release)

	// 4. Sign and verify. The signature carries the actual time, never that
	// of Date: Date can be in the future, one second after the previous
	// state, and sqv rejects signatures from the future.
	signTime := time.Now()
	if in.Now != nil {
		signTime = in.Now()
	}
	var inRelease, releaseGPG bytes.Buffer
	if err := openpgp.SignCleartext(&inRelease, plan.Release, in.Signers, signTime); err != nil {
		return nil, err
	}
	if err := openpgp.SignDetached(&releaseGPG, plan.Release, in.Signers, signTime); err != nil {
		return nil, err
	}
	own := openpgp.NewKeyring(in.Signers...)
	text, infos, err := own.VerifyCleartext(inRelease.Bytes())
	if err != nil || !bytes.Equal(text, plan.Release) || len(infos) != len(in.Signers) {
		return nil, fmt.Errorf("the new InRelease does not verify with the signing keys: %v", err)
	}
	if infos, err := own.VerifyDetached(plan.Release, releaseGPG.Bytes()); err != nil || len(infos) != len(in.Signers) {
		return nil, fmt.Errorf("the new Release.gpg does not verify with the signing keys: %v", err)
	}
	for _, i := range infos {
		res.Signatures = append(res.Signatures, i.Key.String())
	}
	dist := state.Dist()
	dists := append(append([]repo.IndexFile(nil), plan.Indices...),
		repo.IndexFile{Path: dist + "Release", Data: plan.Release},
		repo.IndexFile{Path: dist + "Release.gpg", Data: releaseGPG.Bytes()},
		repo.IndexFile{Path: dist + "InRelease", Data: inRelease.Bytes()},
	)
	if in.OutDir != "" {
		if err := writeOut(in.OutDir, dists); err != nil {
			return nil, err
		}
		in.say("Wrote the new lists and Release files to %s", in.OutDir)
	}

	if in.DryRun {
		for _, u := range plan.PoolUploads {
			in.say("Would upload %s (%s)", u.Path, humanSize(u.Package.Info.Size))
			res.Uploaded = append(res.Uploaded, u.Path)
			res.UploadedBytes += u.Package.Info.Size
		}
		for _, f := range dists {
			in.say("Would write %s", f.Path)
		}
		return res, nil
	}

	var temps []string
	switched := false
	defer func() {
		if err == nil || switched {
			return
		}
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		var left []string
		for _, t := range temps {
			if rerr := st.Remove(cctx, t); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				left = append(left, t)
			}
		}
		if len(left) > 0 {
			err = fmt.Errorf("%w; these temporary files could not be removed: %v", err, left)
		}
	}()

	// 5. Pool files.
	for _, u := range plan.PoolUploads {
		if err := st.MkdirAll(ctx, path.Dir(u.Path)); err != nil {
			return res, fmt.Errorf("creating %s: %w", path.Dir(u.Path), err)
		}
		in.say("Uploading %s (%s)", u.Path, humanSize(u.Package.Info.Size))
		r, err := u.Package.Open()
		if err != nil {
			return res, err
		}
		tmp, err := st.WriteTemp(ctx, u.Path, r)
		r.Close()
		if err != nil {
			return res, fmt.Errorf("uploading %s: %w", u.Path, err)
		}
		temps = append(temps, tmp)
		info, err := st.Stat(ctx, tmp)
		if err != nil {
			return res, err
		}
		if info.Size() != u.Package.Info.Size {
			return res, fmt.Errorf("uploading %s: %d bytes arrived, %d were sent", u.Path, info.Size(), u.Package.Info.Size)
		}
		if err := st.Rename(ctx, tmp, u.Path); err != nil {
			return res, fmt.Errorf("renaming %s: %w", tmp, err)
		}
		temps = temps[:len(temps)-1]
		res.Uploaded = append(res.Uploaded, u.Path)
		res.UploadedBytes += info.Size()
	}

	// 6. Lists and Release as temporary files.
	pending := map[string]string{}
	for _, f := range dists {
		if err := st.MkdirAll(ctx, path.Dir(f.Path)); err != nil {
			return res, fmt.Errorf("creating %s: %w", path.Dir(f.Path), err)
		}
		tmp, err := st.WriteTemp(ctx, f.Path, bytes.NewReader(f.Data))
		if err != nil {
			return res, fmt.Errorf("uploading %s: %w", f.Path, err)
		}
		temps = append(temps, tmp)
		pending[f.Path] = tmp
		info, err := st.Stat(ctx, tmp)
		if err != nil {
			return res, err
		}
		if info.Size() != int64(len(f.Data)) {
			return res, fmt.Errorf("uploading %s: %d bytes arrived, %d were sent", f.Path, info.Size(), len(f.Data))
		}
	}

	// 7. Has another run changed the suite in the meantime?
	if err := checkUnchanged(ctx, st, state); err != nil {
		return res, err
	}

	// 8. Switch, InRelease last.
	switched = true
	for i, f := range dists {
		if err := st.Rename(ctx, pending[f.Path], f.Path); err != nil {
			if i == 0 {
				switched = false
				return res, fmt.Errorf("renaming %s: %w", pending[f.Path], err)
			}
			return res, fmt.Errorf("renaming %s: %w; the suite is half switched and apt reports checksum errors until you run publish again, which completes it", pending[f.Path], err)
		}
		in.say("Switched %s", f.Path)
	}
	in.say("Published %d package(s) to suite %s, Date %s, signed by %s", len(res.Added), in.Suite, res.Date, joinFingerprints(res.Signatures))
	return res, nil
}

// readState reads the state and, if necessary, completes our own run that
// was aborted during switching.
func readState(ctx context.Context, st store.Store, in *Input) (*repo.SuiteState, error) {
	in.say("Reading suite %s from %s", in.Suite, st.Describe())
	state, err := repo.ReadSuite(ctx, st, in.Suite, in.Keyring)
	if err == nil {
		if state.Exists {
			in.say("Suite %s is signed by %s, Date %s", in.Suite, signers(state), repo.FormatDate(state.Date))
		}
		return state, nil
	}
	pending, perr := repo.FindPending(ctx, st, in.Suite, in.Keyring)
	if perr != nil || pending == nil {
		return nil, err
	}
	if in.DryRun {
		return nil, fmt.Errorf("%w\nA previous publish (run %s) stopped while switching; run publish without --dry-run to complete it", err, pending.Run)
	}
	in.say("A previous publish (run %s) stopped while switching suite %s; completing it", pending.Run, in.Suite)
	for _, r := range pending.Renames {
		if err := st.Rename(ctx, r.From, r.To); err != nil {
			return nil, fmt.Errorf("completing the previous publish: renaming %s: %w", r.From, err)
		}
		in.say("Switched %s", r.To)
	}
	return repo.ReadSuite(ctx, st, in.Suite, in.Keyring)
}

// otherSuites reads the lists of the other suites so that Merge knows which
// pool files they reference. Suites whose signature cannot be verified do
// not count; their pool files are then hashed when needed.
func otherSuites(ctx context.Context, st store.Reader, in *Input, res *Result) (map[string]repo.PoolRef, error) {
	suites, err := repo.Suites(ctx, st)
	if err != nil && !errors.Is(err, store.ErrNoListing) {
		return nil, err
	}
	known := map[string]repo.PoolRef{}
	for _, s := range suites {
		if s == in.Suite {
			continue
		}
		state, err := repo.ReadSuite(ctx, st, s, in.Keyring)
		if err != nil {
			in.warn(res, "suite %s is ignored for reusing pool files: %v", s, err)
			continue
		}
		for _, e := range repo.List(state, repo.Filter{}) {
			known[e.Filename] = repo.PoolRef{Size: e.Size, SHA256: e.SHA256, Suite: s}
		}
	}
	return known, nil
}

// checkUnchanged reads InRelease or Release again and compares.
func checkUnchanged(ctx context.Context, st store.Reader, state *repo.SuiteState) error {
	name := "InRelease"
	if state.RawName != "" {
		name = state.RawName
	}
	now, err := st.ReadFile(ctx, state.Dist()+name)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !state.Exists:
		return nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	case !bytes.Equal(now, state.Raw) || errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w: suite %s changed while publishing; run again", ErrBusy, state.Suite)
	}
	if !state.Exists {
		return fmt.Errorf("%w: suite %s was created while publishing; run again", ErrBusy, state.Suite)
	}
	return nil
}

// lock creates the lock; if taken it waits up to in.WaitForLock, every 5 s.
func lock(ctx context.Context, st store.Store, in *Input) error {
	data, err := json.Marshal(in.Lock)
	if err != nil {
		return err
	}
	if in.BreakLock {
		if old, err := st.ReadFile(ctx, repo.LockFile); err == nil {
			in.say("Breaking the lock %s: %s", repo.LockFile, bytes.TrimSpace(old))
			if err := st.Remove(ctx, repo.LockFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	deadline := time.Now().Add(in.WaitForLock)
	for {
		err := st.CreateExclusive(ctx, repo.LockFile, append(data, '\n'))
		if err == nil {
			return nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("creating the lock %s: %w", repo.LockFile, err)
		}
		owner := "unknown"
		var held LockInfo
		if old, err := st.ReadFile(ctx, repo.LockFile); err == nil && json.Unmarshal(old, &held) == nil {
			owner = fmt.Sprintf("%s@%s, pid %d, suite %s, wdyapt %s, started %s ago", held.User, held.Host, held.PID, held.Suite, held.Version, time.Since(held.Started).Round(time.Second))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: the repository is locked by another publish (%s); wait for it, use --wait-for-lock, or --break-lock if it was interrupted", ErrBusy, owner)
		}
		in.say("The repository is locked by another publish (%s); waiting", owner)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(min(5*time.Second, time.Until(deadline)+time.Millisecond)):
		}
	}
}

// writeOut also stores the new files locally.
func writeOut(dir string, files []repo.IndexFile) error {
	for _, f := range files {
		name := filepath.Join(dir, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(name, f.Data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func signers(s *repo.SuiteState) string {
	var fps []string
	for _, i := range s.Signers {
		fps = append(fps, i.Signer.String())
	}
	if len(fps) == 0 {
		return "nobody checked"
	}
	return joinFingerprints(fps)
}

func joinFingerprints(fps []string) string {
	var b bytes.Buffer
	for i, f := range fps {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(f)
	}
	return b.String()
}

// humanSize writes a size in human-readable form.
func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

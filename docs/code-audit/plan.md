# Remediation Plan

Sequenced fixes for the issues in [`findings.md`](findings.md). Phases are ordered
by risk-reduction per unit of effort and are independently landable — each is a
self-contained PR that leaves the tree green.

Finding IDs (F1–F19) refer to [`findings.md`](findings.md). F17–F19 come from the
re-review of `accbbd38..12d21229` and are addressed in [Phase 1](#phase-1) (1.5)
and [Phase 4](#phase-4) (4.6).

## Phase 0: Restore analyzer coverage (prerequisite)

The audit could not run `go vet`, `staticcheck`, or `golangci-lint` — the module
cache was empty and the sandbox blocked the module proxy. **Do this first**, in a
network-enabled environment, before writing any fix. It may surface issues this
manual review missed, and it establishes the baseline that later phases are
checked against.

```bash
go mod download && go vet ./... && staticcheck ./... && golangci-lint run
```

Then add the analyzers this audit substituted for by hand:

```bash
go run github.com/kisielk/errcheck@latest ./...
go run github.com/gordonklaus/ineffassign@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@latest ./...
```

`errcheck` is the highest-value addition: it would have found F7 and F13
mechanically. If CI does not already gate on `golangci-lint`, wiring it up with
`errcheck`, `ineffassign`, and `staticcheck` enabled is worth more long-term than
any single fix below.

Triage the output against this document before proceeding — if the analyzers
disagree with a finding here, trust the analyzer and re-verify.

## <a id="phase-1"></a>Phase 1: Memory-safety and crash fixes

Five independent, small, high-severity fixes. Land these first.

### 1.1 Use per-architecture syscall numbers (F1)

`pkg/mempolicy/mempolicy.go`

Replace the hardcoded constants with `golang.org/x/sys/unix`, already a direct
dependency:

```go
import "golang.org/x/sys/unix"

// then use unix.SYS_SET_MEMPOLICY / unix.SYS_GET_MEMPOLICY
```

Drop the local `SYS_SET_MEMPOLICY`/`SYS_GET_MEMPOLICY` declarations. Prefer
`unix.Syscall` over `syscall.Syscall` for consistency with the constants.

Add `//go:build linux` to the file. These are Linux-only syscalls and the package
currently compiles on any GOOS, which is how the architecture assumption went
unnoticed. If a non-Linux build of the containing package is needed, add a stub
returning a "not supported on this platform" error rather than a `panic` —
`pkg/cgroups/cgroupid_other.go` is the existing (panicking) precedent, but an
error is better here since the caller can degrade gracefully.

**Verification.** `GOOS=linux GOARCH=arm64 go build ./pkg/mempolicy/` must
compile. Confirm the resolved constants differ per arch:

```bash
GOARCH=arm64 go vet ./pkg/mempolicy/ && GOARCH=amd64 go vet ./pkg/mempolicy/
```

A unit test cannot easily assert the syscall number, but a test that
`SetMempolicy(MPOL_DEFAULT, []int{0})` returns without error on a Linux CI runner
is worth adding — under the current code on arm64 it would invoke
`migrate_pages` and behave observably differently.

**Also consider** adding `TARGETARCH` handling to the `Dockerfile`s. The audit
found none, and `docker buildx build --load` on an arm64 host silently produces an
arm64 image today. Being explicit about supported architectures — or gating the
build — prevents a recurrence.

### 1.2 Fix mask sizing and bounds (F2)

`pkg/mempolicy/mempolicy.go`

Three coupled changes; do them together since they share the `maxnode` contract.

Have `nodesToMask` return the node count alongside the mask so the caller passes
the correct `maxnode` (highest node number + 1) rather than deriving
`len(mask)*64`:

```go
func nodesToMask(nodes []int) (mask []uint64, maxnode int, err error)
```

In `GetMempolicy`, allocate one word more than the declared `maxnode` requires so
the kernel cannot write past the buffer — `make([]uint64, MAX_NUMA_NODES/64 + 1)`
— or pass `maxNode = MAX_NUMA_NODES - 1`. Pick one and state the invariant in a
comment; the current code has neither.

Make `maskToNodes` bound its loop by the slice it was given:

```go
for i := 0; i < len(mask)*64 && i < MAX_NUMA_NODES; i++ {
```

**Verification.** Table-driven unit tests on `nodesToMask`/`maskToNodes` — pure
functions, no syscall needed. Cover: empty set, `{0}`, `{63}`, `{64}` (word
boundary), `{0,1}`, `{1023}`, and `{1024}` (must error). Assert
`maskToNodes(mask) == nodes` round-trips for each, and that `maskToNodes` on a
1-word mask does not panic. These tests fail against the current code.

### 1.3 Check the `LookupPod` result (F3)

`pkg/resmgr/nri.go:381-384`

```go
m.Lock()
defer m.Unlock()

pod, ok := m.cache.LookupPod(podSandbox.GetId())
if !ok {
    nri.Warnf("%s: unknown pod %s, nothing to release", event, podSandbox.GetId())
    return nil
}
released := slices.Clone(pod.GetContainers())
```

Note the `ok` check is what matters — a `pod != nil` guard does **not** work here,
because `LookupPod` returns a typed-nil `*pod` inside a non-nil `Pod` interface.

Resolve the `TODO` at line 381 in the same change by adding the lock, matching
the six sibling handlers. Order matters: take the lock before the cache access,
and keep it held across `runPostReleaseHooks` only if the other handlers do —
check whether the hooks re-enter the resmgr before widening the critical section,
since `runPostReleaseHooks` calls into policy code.

**Verification.** Unit test calling `StopPodSandbox` with an ID absent from the
cache; it panics today. Then run the e2e suite with `-race` (debug builds already
enable it, `Makefile:122`).

### 1.4 Fix `Shutdown` nil-channel receive (F4)

`pkg/http/http.go:191-215`

Guard the receive:

```go
if sync != nil {
    <-sync
}
```

Two things to fix while there. Rename the variable — `sync` shadows the imported
`sync` package inside this function, which is legal but hostile to readers.
And move the wait **outside** the `s.Lock()` critical section: as written, a slow
graceful shutdown blocks every concurrent `ServeHTTP` (which takes `s.RLock()`),
turning a slow shutdown into a hung endpoint. Snapshot `s.server` under the lock,
release it, then wait.

Consider also whether `Shutdown` should take a `context.Context` instead of a
`bool`. It currently hardcodes `context.Background()` (line 209), so a graceful
shutdown has no timeout and can hang indefinitely on a wedged connection. Since
the method has no in-tree callers, changing the signature is free right now — this
is the cheapest moment to get the API right.

**Verification.** Unit test: `Start` on `:0`, then `Shutdown(false)` with a
timeout guard around it — hangs today. Add a `Shutdown(true)` case, and one with
an in-flight request to confirm the lock is not held across the wait.

### 1.5 Create `doneC` and fix the shutdown ordering (F18, F17)

`pkg/agent/agent.go:154,171,213,267-274`

Two changes that must land together, in this order.

**First, make `doneC` real.** Initialize it in `New()` alongside `stopC`, and close
it when the event loop returns:

```go
// New():
stopC: make(chan struct{}),
doneC: make(chan struct{}),

// Start(), immediately before the event loop:
defer close(a.doneC)
for {
	select {
	case <-a.stopC:
```

Place the `defer` immediately before `for {`, not at the top of `Start()`. The
setup calls above it (`setupClients`, `setupNodeWatch`, `setupNodeConfigWatch`)
each have early error returns; closing `doneC` on those paths would let a later
`Stop()` return while claiming the loop had run.

**Then reorder `Stop()`** so cleanup happens after the loop has drained:

```go
func (a *Agent) Stop() {
	a.stopLock.Lock()
	defer a.stopLock.Unlock()

	if a.stopC != nil {
		close(a.stopC)
		<-a.doneC
		a.stopC = nil
		a.clearOwnConfigStatus()
	}
}
```

This removes the `currentCfg` data race without introducing a mutex: after
`<-a.doneC` there is no concurrent writer, because the only writer is the event
loop that has now returned. Do not reorder before fixing `doneC` — with a nil
channel, everything after the receive is unreachable.

Consider also whether the 10-second timeout in `clearOwnConfigStatus` belongs on
the SIGTERM path at all. The kubelet's termination grace period is finite and
shared with the extended-resource cleanup; a wedged API server can consume it here
and get the process SIGKILLed, losing both cleanups. Deriving both timeouts from a
single shutdown deadline is the more robust shape, but it is a larger change and
should be separate.

**Verification.** A `-race` unit test is the point of this fix: run `Start` in a
goroutine, drive a config update concurrently with `Stop()`, and assert `Stop()`
returns within a timeout. That test fails three ways against today's code (hangs
on nil `doneC`; reports a race on `currentCfg` once `doneC` is fixed; passes only
after the reorder). Use a fake `ConfigInterface` recording `PatchStatus` calls to
assert the null-status patch is still sent exactly once.

## <a id="phase-2"></a>Phase 2: Concurrency correctness

Ordered so the ownership question (2.1) is settled before the fixes that depend
on knowing who locks what.

### 2.1 Decide and document cache lock ownership (F5)

`pkg/resmgr/cache/cache.go:529`

Settle this first — 2.2 and Phase 3's F10 fix both depend on the answer.

**Recommendation: remove the embedded `sync.Mutex`** and document that callers
must serialize. Rationale: `resmgr`'s `RWMutex` already spans whole NRI
transactions, which is the correct granularity — a policy decision performs many
cache reads and writes that must be atomic *as a unit*. Per-method locking inside
the cache would add no safety at that level while creating a false impression
that the cache is independently safe, which is precisely the misreading that
produced F3.

```go
// cache is our internal cache of pods and containers.
//
// The cache is NOT internally synchronized. Callers must serialize all
// access; the resource manager does so by holding its own lock across
// entire NRI request transactions (see pkg/resmgr/nri.go).
type cache struct {
	filePath string
	...
```

Removing the field also cleans up the `json:"-"` tag on a struct that is
serialized.

If instead the decision is to make the cache self-synchronizing, it must be all
exported methods, with the transaction-level lock retained on top — and the
`Save`/`Snapshot` path needs care to avoid marshalling under a held lock.

**Verification.** `go build ./...` plus e2e with `-race`. Removal is
compile-checked: any actual `cch.Lock()` caller would break the build, and the
audit found none.

### 2.2 Create the wait channel before spawning the goroutine (F6)

`pkg/resmgr/cache/pod.go:144-155`

Move both field assignments out of the goroutine so they are visible to the
caller before `goFetchPodResources` returns:

```go
func (p *pod) goFetchPodResources(ch <-chan *podresapi.PodResources) {
	if ch == nil {
		return
	}
	p.podResCh = ch
	p.waitResCh = make(chan struct{})

	go func() {
		defer close(p.waitResCh)
		p.PodResources = <-ch
		log.Debugf(...)
	}()
}
```

This fixes the ordering bug — `GetPodResources` can no longer observe
`waitResCh == nil` and skip the wait. The remaining write to `p.PodResources`
inside the goroutine, read by `GetPodResources` after `<-p.waitResCh`, is then
properly ordered by the channel close.

`setPodResources` (line 157) still writes the same field from the resync path
with no coordination. Check whether both paths can be live for one pod
simultaneously: `RefreshPods` calls `InsertPod(item, nil)` with a nil channel
(`cache.go:749`), so in the current call graph they appear mutually exclusive. If
that holds, document the invariant in a comment; if not, the field needs
guarding.

**Verification.** Run the e2e suite with `-race`. A focused test is better:
call `goFetchPodResources` then immediately `GetPodResources` from another
goroutine and assert the fetched value is returned — this is racy today and
`-race` should flag the `waitResCh` access.

### 2.3 Release the healthz lock before invoking callbacks (F8)

`pkg/healthz/healthz.go:89-109`

Snapshot under the lock, call outside it:

```go
func check() (Status, map[string]error) {
	lock.Lock()
	names := slices.Clone(sorted)
	fns := make([]CheckFn, len(names))
	for i, name := range names {
		fns[i] = checkers[name]
	}
	lock.Unlock()

	status, details := Healthy, map[string]error{}
	for i, fn := range fns {
		if s, err := fn(); s != Healthy {
			...
		}
	}
	return status, details
}
```

Consider also giving `check()` a context so a wedged checker cannot hang the
`/healthz` handler indefinitely — a health endpoint that never answers is worse
than one that answers "unhealthy". Out of scope for the lock fix; worth a
follow-up issue.

Separately, `RegisterHealthChecker` panics on duplicate registration (line 80).
Returning an error is friendlier, though as an init-time fail-fast the panic is
defensible — leave it unless the registration path becomes dynamic.

**Verification.** Unit test registering a checker that itself calls
`RegisterHealthChecker` — deadlocks today. A second test with a checker that
blocks on a channel, asserting a concurrent `/healthz` still completes.

### 2.4 Hold the meter lock across the whole iteration (F9)

`cmd/plugins/balloons/policy/metrics.go:105-125`

Acquire once around the loop rather than per element, and split `Observe` so the
locked and unlocked parts are explicit:

```go
_, err = m.meter.RegisterCallback(
	func(ctx context.Context, o metric.Observer) error {
		m.p.RequestMeters()
		defer m.p.ReleaseMeters()

		for _, bln := range m.p.balloons {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				m.observeLocked(o, bln)
			}
		}
		return nil
	},
	m.balloon,
)
```

Rename `Observe` → `observeLocked` (dropping its internal
`RequestMeters`/`ReleaseMeters`) so the precondition is visible at every call
site. Note `meterLock`'s inverted polarity — `RequestMeters` takes the
*exclusive* `Lock` and the allocation side takes `RLock` — so holding it across
the loop blocks allocation for the duration of a scrape. That is the correct
trade for a consistent snapshot, but keep `observeLocked` free of I/O and
allocation-path calls so the window stays short.

The `ctx.Done()` branch currently logs an error and *continues looping*
(line 109); returning `ctx.Err()` is the right behaviour on cancellation.

**Verification.** `-race` while scraping metrics concurrently with pod
churn. The e2e balloons suite with a scrape loop against `/metrics` should
reproduce the slice race today.

## Phase 3: Efficiency

### 3.1 Short-circuit disabled log levels (F11)

`pkg/log/slog.go:91-116`

**Highest leverage change in this plan** — one edit, ~557 call sites, no caller
changes. Add a level check before formatting:

```go
func (l *slogger) Debugf(format string, args ...any) {
	if !l.Enabled(l.ctx, LevelDebug) {
		return
	}
	l.Log(LevelDebug, fmt.Sprintf(format, args...))
}
```

Use whatever check `Log` already performs internally so behaviour cannot diverge —
`DebugEnabled()` (line 168) delegates to `cfg.Debugging(l.source)`, and the
handler has its own `Enabled`. Verify which is authoritative before picking, and
apply the same pattern to `Infof`/`Warnf`/`Errorf` and to `LogBlock` (line 122),
which additionally splits and allocates a slice.

Do **not** short-circuit `Fatalf` or `Panicf` — they must still exit or panic even
when the level is disabled.

This does not help arguments that are expensive to *evaluate*, since those are
computed at the call site before the call. After landing, guard the worst
offenders individually with `if log.DebugEnabled()`:

- `pkg/resmgr/cache/pod.go:152,159` — `%+v` on a whole `*PodResources`
- the 13 `%+v` struct-formatting sites
- any `Debugf` whose argument calls a `PrettyPrint`/`String` helper, e.g.
  `pkg/cpuallocator/allocator.go:215`

**Verification.** Existing log tests must still pass — assert output is unchanged
when the level is enabled, and absent when disabled. A benchmark on a hot
`Debugf` with debug off makes the win concrete:

```bash
go test -bench=. -benchmem ./pkg/log/
```

### 3.2 Batch cache saves during resync (F10)

`pkg/resmgr/cache/cache.go:738`

Wrap the `RefreshPods` body using the existing, currently-unused suppression
counter:

```go
func (cch *cache) RefreshPods(...) ([]Pod, []Pod, []Container) {
	cch.BlockSave()
	defer func() {
		if err := cch.UnblockSave(); err != nil {
			log.Warnf("failed to save cache after refresh: %v", err)
		}
	}()
	...
```

Use `defer` specifically — `UnblockSave` self-heals a negative counter
(line 1222), which suggests prior trouble with unbalanced manual calls.

Audit other loops that call `InsertPod`/`DeletePod`/`InsertContainer`/
`DeleteContainer` repeatedly for the same amplification; `RefreshPods` is the one
this audit confirmed, not necessarily the only one.

If Phase 2.1 removed the cache mutex, note that `saveBlock` remains a plain `int`
relying on the external resmgr lock — consistent with the documented contract, but
call it out in the comment.

**Verification.** Unit test with a fake NRI pod list of ~100 pods, counting
`Save` invocations (inject a hook or count file writes): expect 1, not 100.
Assert the on-disk cache content is identical before and after the change — this
must be a pure performance fix.

## <a id="phase-4"></a>Phase 4: Correctness polish and idiom cleanup

Low-risk, mechanical. Can land as one PR or be folded into unrelated work.

### 4.1 Propagate deferred close errors (F7)

Add named results to the five functions that capture close errors into a
discarded local:

| File | Function | Change |
|------|----------|--------|
| `pkg/cgroups/cgroupcontrol.go:156` | `Group.Write` | `error` → `(err error)` |
| `pkg/cgroups/cgroupcontrol.go:200` | `Group.writePids` | `error` → `(err error)` |
| `pkg/resmgr/cache/cache.go:1319` | `cache.WriteFile` | `error` → `(err error)` |
| `cmd/config-manager/main.go:122` | `configureNriForCrio` | `error` → `(err error)` |
| `cmd/config-manager/main.go:147` | `writeToContainerdConfig` | `error` → `(err error)` |

`pkg/sysfs/utils.go:149` already does this correctly — follow it.

`writeToContainerdConfig` needs one extra step: it ends with `return w.Flush()`,
so naming the result is not sufficient — assign the flush error first
(`err = w.Flush(); return err`) so the deferred close can observe and preserve it.
Otherwise a failed flush still masks a failed close.

Adding a named result changes each function's `return nil` sites to still return
nil while letting the deferred assignment take effect, so **behaviour changes**:
callers will start seeing close errors they previously did not. That is the point,
but for the cgroup writers it means previously-silent kernel rejections
(`EINVAL` on an out-of-range limit, `EBUSY`) now surface as errors. Check each
caller handles a newly non-nil error sanely before landing — a plugin that now
fails a container update where it used to silently continue is a behaviour
regression even though the new behaviour is more correct.

**Verification.** `errcheck` from Phase 0 should stop flagging these. Unit test
against a file whose `Close` fails — a `/proc` or cgroup pseudo-file that rejects
the written value at close time is the realistic case.

### 4.2 Fix the two wrong-variable bugs (F12, F13)

`pkg/apis/resmgr/v1alpha1/expression.go:78-79` — swap the arguments to match the
message:

```go
return exprError("invalid expression, trailing key %q after %q", restKey, prefKey)
```

`pkg/cgroups/cgroupcontrol.go:193` — report the scanner error, not the stale
`err`:

```go
if serr := s.Err(); serr != nil {
	return nil, g.errorf("failed to read %q: %v", entry, serr)
}
```

**Verification.** For F12, a table test on `Expression.Validate` asserting the
message text for input `"name/extra"` — pins the fix and guards regression. F13 is
hard to unit test (needs a read error mid-scan); careful review suffices.

### 4.3 Guard tar extraction against traversal (F14)

`pkg/testutils/tar.go`

Validate each joined path stays within the destination, for all three entry
types, and validate `header.Linkname` for symlinks:

```go
target := filepath.Join(dir, header.Name)
if !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
	return fmt.Errorf("tar entry %q escapes destination directory", header.Name)
}
```

For `tar.TypeSymlink`, additionally reject absolute `Linkname` and any link
resolving outside `dir` — an unvalidated symlink is the more dangerous half, since
a later entry can write through it.

Switch `path` to `path/filepath` while there (line 22): `path` is for slash-separated
URLs, `filepath` for OS paths, and the containment check above depends on
OS-correct separators.

Test-only code, so this is hygiene rather than an exploitable hole — but it is a
tempting copy-paste source. Keep the "must not be used in production" comment.

### 4.4 Error-string conventions and `%w` (F15)

Lowercase the ~20 capitalized error strings, rewording where the leading token is
a proper noun (`"SST init failed"` → `"failed to initialize SST"`) rather than
just lowercasing an identifier. Drop redundant function names from messages that
the wrap chain already conveys — `pkg/utils/parse.go:30`'s `"ParseEnabled: ..."`
is the clearest case.

The 130 `%v`-on-error sites are a **separate PR**, and not purely mechanical:
switching to `%w` widens each function's API contract, since callers gain the
ability to match the wrapped type with `errors.Is`/`errors.As`. Convert
deliberately, package by package, starting where sentinel matching is actually
wanted. `pkg/sysfs` already uses `%w` and is the model.

**Verification.** `staticcheck ./...` (ST1005) from Phase 0 should come back
clean on the reworded strings.

### 4.5 Idiom modernization (F16)

Opportunistic only — a tree-wide rewrite churns history for no functional gain.
Prefer doing these in files already being touched for other reasons.

- `ioutil.Discard` → `io.Discard` at
  `pkg/apis/config/v1alpha1/log/klogcontrol/gen-config.go:33`. One line, do it
  now; it is the last `ioutil` use in the tree.
- `interface{}` → `any` (104 sites). Gofmt-able but touches many files.
- `sort` → `slices` (18 files). **Not a blind substitution**: `sort.Slice` is not
  stable, so any site relying on incidental stability needs
  `slices.SortStableFunc`, not `slices.SortFunc`. Review each comparator.
- Reconsider `panic` at `pkg/utils/cpuset/cpuset.go:37` and
  `pkg/kubernetes/resources.go:193,208`, which turn recoverable input errors into
  a plugin crash. Returning an error is better, but changes signatures — treat as
  its own change with caller review.

### 4.6 Harden the CPU hint consumer (F19)

`cmd/plugins/balloons/policy/cputree.go:715,723`

Two robustness fixes in `resizeCpusWithDevices`. Neither is a live bug today; both
become more reachable now that `c17a6b31` lets one cpuclass hint contribute several
candidate sets.

**Guard the shrink-path index.** Line 723 indexes `leastHintedCpus[-delta]`, which
is in range only because `resizeCpusOnlyIfNecessary` rejected `-delta >=
currentCpus.Size()` four resizers earlier. Make the invariant local:

```go
if -delta >= len(leastHintedCpus) {
    return freeCpus, currentCpus, fmt.Errorf(
        "internal error: cannot release %d of %d CPUs", -delta, len(leastHintedCpus))
}
```

**Replace the exponential hint weights.** Line 715 accumulates
`1 << (len(allCloseCpuSets) - 1 - hintPriority)` into a `uint64`, which caps the
usable device count at 64 and degrades silently — not with an error — past it.
Sort by `(hintPriority, cpu)` rank instead of summing powers of two: the code only
needs a total order over CPUs by best-hint-priority, which a rank comparison gives
without a width limit. This is the more invasive of the two; if it is deferred, at
minimum log a warning when `len(allCloseCpuSets) > 64` so the collapse is visible.

**Verification.** Table-driven unit tests on `resizeCpusWithDevices` with a
synthetic tree: one case per tier with multiple candidate sets, one shrink case at
`-delta == len(currentCpus)-1` (the boundary), and one with 65 hint devices
asserting the priority order still holds. The existing
`TestMergeCpuClassHintsNoAccumulation` covers the producer side; this is the gap on
the consumer side.

## Suggested PR sequence

| PR | Contents | Risk |
|----|----------|------|
| 0 | Analyzer baseline + CI gate (Phase 0) | none |
| 0b | Agent `doneC` + shutdown reorder (1.5) | low — but verify with `-race` |
| 1 | mempolicy syscalls, mask arithmetic, build tag (1.1, 1.2) | low, well-tested |
| 2 | `StopPodSandbox` nil check + lock (1.3) | low |
| 3 | `http.Shutdown` (1.4) | low, no callers |
| 4 | Cache lock ownership decision + docs (2.1) | low, compile-checked |
| 5 | Pod-resource race (2.2) | medium — verify with `-race` |
| 6 | healthz lock (2.3) | low |
| 7 | balloons meter lock (2.4) | medium — verify with `-race` |
| 8 | Log level short-circuit (3.1) | low, high payoff |
| 9 | Cache save batching (3.2) | low |
| 10 | Deferred close errors (4.1) | **medium — changes error behaviour** |
| 11 | Wrong-variable fixes, tar guard, error strings (4.2–4.4) | low |
| 12 | CPU hint consumer hardening (4.6) | low — pure robustness |

PRs 1–3 are independent and can land in parallel. PR 4 should precede 5 and 9,
since both depend on the documented locking contract. PR 10 needs the most caller
review despite its small diff — it is the only change that makes previously-silent
failures visible.

PR 0b is listed early because it is a two-line initialization plus a reorder, and
because the graceful-shutdown path is currently non-functional in a way that masks
future work there: anything added after `<-a.doneC` is dead code until `doneC`
exists. It is independent of PRs 1–3 and can land alongside them. PR 12 is
independent of everything else and can land whenever convenient.

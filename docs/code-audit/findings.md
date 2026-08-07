# Go Source Code Audit: Findings

Audit of the `nri-plugins` Go sources (252 non-vendored files, ~61k lines) covering
correctness, non-idiomatic Go, inefficiencies, and security-relevant patterns.

Date of audit: 2026-08-07. Audited tree: `main` at `accbbd38`.

Re-reviewed 2026-08-07 against `main` at `12d21229` (five new commits). See
[Addendum](#addendum) for findings F17-F19 and for corrections to F7 and F10.

## Method and its limits

Findings were derived by reading source and by targeted pattern searches. **No
compiler- or analyzer-backed verification was performed**: the Go module cache in
the audit environment was empty and the sandbox had no access to the module proxy,
so `go vet`, `staticcheck`, and `golangci-lint` could not run. Every finding below
was hand-verified by reading the relevant code, and the arithmetic claims in F1/F2
were checked with a standalone reproduction, but the audit has the coverage
characteristics of a manual review rather than an exhaustive analyzer sweep.

Re-running the toolchain in a network-enabled environment is recommended as a
complement — see [`plan.md`](plan.md), Phase 0. In particular `errcheck`,
`ineffassign`, and `gosec` cover ground this audit only sampled.

## Severity summary

| ID | Severity | Area | Issue |
|----|----------|------|-------|
| [F1](#f1) | High | `pkg/mempolicy` | Hardcoded syscall numbers are wrong on non-amd64; invokes `migrate_pages`/`move_pages` on arm64 |
| [F2](#f2) | High | `pkg/mempolicy` | `maxnode` argument miscomputed; `maskToNodes` reads a short buffer |
| [F3](#f3) | High | `pkg/resmgr` | `StopPodSandbox` nil-pointer dereference on unknown pod, plus unsynchronized cache access |
| [F4](#f4) | High | `pkg/http` | `Server.Shutdown(false)` deadlocks forever on a nil channel |
| [F5](#f5) | Medium | `pkg/resmgr/cache` | Embedded `sync.Mutex` is never locked by any caller |
| [F6](#f6) | Medium | `pkg/resmgr/cache` | Pod-resource fetch goroutine races on the fields it publishes |
| [F7](#f7) | Medium | `pkg/cgroups` | Deferred close error assigned to a discarded local, not a named return |
| [F8](#f8) | Medium | `pkg/healthz` | Health-check callbacks invoked while holding a global lock |
| [F9](#f9) | Medium | balloons policy | Metrics callback iterates `b.balloons` unlocked before taking the lock |
| [F10](#f10) | Medium | `pkg/resmgr/cache` | `RefreshPods` triggers one full cache serialization per pod |
| [F11](#f11) | Medium | `pkg/log` | `Debugf`/`Tracef` format eagerly regardless of level (557 call sites) |
| [F12](#f12) | Low | `pkg/apis/resmgr` | Swapped format arguments in a validation error message |
| [F13](#f13) | Low | `pkg/cgroups` | `readPids` reports the wrong error variable |
| [F14](#f14) | Low | `pkg/testutils` | Tar extraction has no path-traversal guard |
| [F15](#f15) | Low | various | Error-string convention violations (`ST1005`) |
| [F16](#f16) | Low | various | `interface{}` over `any`; `sort` over `slices`; one `ioutil` use |
| [F17](#f17) | High | `pkg/agent` | `clearOwnConfigStatus` performs a blocking API call from the signal goroutine and races on `currentCfg` |
| [F18](#f18) | High | `pkg/agent` | `Agent.doneC` is never created; `Stop()` blocks forever on a nil channel |
| [F19](#f19) | Medium | balloons policy | Hint consumer panics on an unexpected `delta`, and hint priority weights overflow past 64 devices |

---

## High severity

### <a id="f1"></a>F1. Hardcoded mempolicy syscall numbers are architecture-specific

`pkg/mempolicy/mempolicy.go:39-40` hardcodes Linux syscall numbers:

```go
SYS_SET_MEMPOLICY = 238
SYS_GET_MEMPOLICY = 239
```

These are the **amd64** numbers. The file carries no build constraint, so it
compiles and runs on every architecture. On arm64 those same numbers mean
something else entirely:

| Number | amd64 | arm64 |
|--------|-------|-------|
| 236 | — | `get_mempolicy` |
| 237 | — | `set_mempolicy` |
| 238 | `set_mempolicy` | **`migrate_pages`** |
| 239 | `get_mempolicy` | **`move_pages`** |

(Verified against `golang.org/x/sys/unix/zsysnum_linux_{amd64,arm64}.go`.)

On arm64, `SetMempolicy` invokes `migrate_pages` and `GetMempolicy` invokes
`move_pages`, with arguments that mean different things. This is not a clean
failure: `migrate_pages(pid, maxnode, old_nodes)` will be called with the mode
value reinterpreted as a **PID**. With `mpol=0` (`MPOL_DEFAULT`) that is
`pid == 0`, i.e. the calling process, so the kernel will attempt an actual page
migration driven by a pointer that the caller intended as a node mask. Silent
memory-placement corruption is the likely outcome, not `ENOSYS`.

`golang.org/x/sys v0.45.0` is already a direct dependency (`go.mod:38`) and
exports the correct per-architecture constants, so the fix requires no new
dependency.

**Impact.** Wrong syscall invoked on any non-amd64 build. The `mpolset` binary
and the `memory-policy` plugin that injects it are affected. Note that the
`Dockerfile`s specify no `TARGETARCH` and the `Makefile` uses
`docker buildx build --load`, so an arm64 image is produced by simply building on
an arm64 host — no explicit cross-build step is needed to hit this.

### <a id="f2"></a>F2. `maxnode` miscomputed and `maskToNodes` over-reads

Two distinct arithmetic defects in the same file.

**(a) `SetMempolicy` passes the wrong `maxnode`** — `mempolicy.go:102`:

```go
_, _, errno := syscall.Syscall(SYS_SET_MEMPOLICY, uintptr(mpol),
    uintptr(nodeMaskPtr), uintptr(len(nodeMask)*64))
```

`nodesToMask` sizes the mask to `(maxNode/64)+1` words, so for nodes `{0,1}` it
allocates 1 word and passes `maxnode = 64`. The kernel treats `maxnode` as a bit
count and validates the mask as holding `maxnode+1` bits — 65 bits, i.e. 2 words,
against a 1-word allocation. The kernel's `get_nodes`/`copy_nodes_to_user` path
rounds to `BITS_TO_LONGS(maxnode+1)` longs, so it reads past the slice. The
correct value to pass is the highest node number plus one, not
`len(mask) * 64`.

**(b) `GetMempolicy` under-allocates relative to the `maxnode` it declares** —
`mempolicy.go:112-113`:

```go
maxNode := uint64(MAX_NUMA_NODES)      // 1024
nodeMask := make([]uint64, maxNode/64) // 16 words = 1024 bits
```

The buffer holds exactly 1024 bits while `maxnode = 1024` tells the kernel it may
write bit index 1024 — the 1025th bit, one word beyond the allocation. Same
off-by-one as (a), in the opposite direction.

**(c) `maskToNodes` assumes a full-size mask** — `mempolicy.go:85-93`:

```go
func maskToNodes(mask []uint64) []int {
	nodes := make([]int, 0)
	for i := range MAX_NUMA_NODES {           // 0..1023 unconditionally
		if (mask[i/64] & (1 << (i % 64))) != 0 {
```

The loop indexes `mask[0..15]` regardless of `len(mask)`. It happens not to panic
today because its only caller passes a 16-word slice, but the function is a
package-level helper with no bounds check and no documented precondition; any
future caller passing a mask sized by `nodesToMask` (which returns as little as
one word) panics with an index-out-of-range.

**Impact.** Out-of-bounds kernel writes into a Go-managed buffer, and a latent
panic. (a) and (b) are memory-safety issues, not merely cosmetic off-by-ones.

### <a id="f3"></a>F3. `StopPodSandbox` dereferences a nil pod and skips locking

`pkg/resmgr/nri.go:381-384`:

```go
// TODO(klihub): shouldn't we m.Lock()/defer m.Unlock() here?

pod, _ := m.cache.LookupPod(podSandbox.GetId())
released := slices.Clone(pod.GetContainers())
```

Two problems, both flagged by the pre-existing `TODO`.

The `ok` result of `LookupPod` is discarded. `LookupPod` returns
`(Pod, bool)` where the interface value is a `*pod` read straight out of a map
(`cache.go:651-654`), so a miss yields a **typed nil** `*pod` wrapped in a
non-nil `Pod` interface. The subsequent `pod.GetContainers()` (`pod.go:47-57`)
dereferences it as `p.cache.Containers` — a nil-pointer panic, not a graceful nil
check. Because the interface is non-nil, a `pod != nil` guard would not help; the
`ok` value must be checked. Every other NRI handler in the file checks this
result.

Separately, this is the only NRI handler that touches the cache without holding
`m.Lock()`; the six others (lines 359, 428, 453, 524, 570, 632, 671) all do. See
F5 for why the resmgr lock — not the cache's own mutex — is what actually
protects cache state.

**Impact.** A `StopPodSandbox` for a pod the plugin never saw (a restart with
pre-existing pods, or a stale runtime retry) panics the plugin. Concurrently, an
unsynchronized read of `cch.Containers` races against writers holding only
`m.Lock()`.

### <a id="f4"></a>F4. `Server.Shutdown(false)` blocks forever

`pkg/http/http.go:191-215`:

```go
func (s *Server) Shutdown(wait bool) {
	var sync chan struct{}          // nil
	...
	if wait {
		sync = make(chan struct{})
		s.server.RegisterOnShutdown(func() { close(sync) })
	}
	if err := s.server.Shutdown(...); err != nil { ... }
	<-sync                          // unconditional receive
```

`sync` is only assigned when `wait` is true. When `wait` is false it stays nil,
and a receive from a nil channel blocks forever. The `wait` parameter therefore
inverts its own meaning: `wait=false` hangs, `wait=true` returns.

The goroutine blocks while holding `s.Lock()` (acquired at line 196 with
`defer`), so the whole `Server` is wedged: `Start`, `Stop`, `Restart`, and every
`ServeHTTP` (which takes `s.RLock()`) block behind it. This escalates a hung
shutdown into a hung metrics/healthz endpoint.

No in-tree caller invokes this method today, so it is currently unreachable —
which is exactly why it has survived. It is exported API and will misbehave on
first use.

---

## Medium severity

### <a id="f5"></a>F5. The cache's embedded mutex is never used

`pkg/resmgr/cache/cache.go:529` embeds a mutex in the cache struct:

```go
type cache struct {
	sync.Mutex `json:"-"` // we're lockable
```

A repository-wide search for `Lock()` on a cache value returns **no callers** —
not in `pkg/resmgr/cache`, not in `pkg/resmgr`, not in either policy. All
serialization comes from the separate `sync.RWMutex` embedded in `resmgr`
(`resource-manager.go:52`), taken by the NRI handlers.

Two consequences:

1. The comment `// we're lockable` documents a guarantee that does not hold. Any
   contributor who reads the struct and concludes the cache is self-synchronizing
   will write racy code. F3 is arguably this mistake already made.
2. The mutex is dead weight in a struct that is copied and serialized.

The mutex should either be used consistently inside the cache's exported methods,
or removed with a comment stating that callers must serialize externally. Given
that `resmgr` already holds a lock across whole NRI transactions (which is the
correct granularity — a policy decision spans many cache reads and must be
atomic as a unit), **removing** the mutex and documenting the contract is the
better fix. Adding per-method locking inside the cache would provide no
additional safety at the transaction level while creating a false impression that
it does.

### <a id="f6"></a>F6. Pod-resource fetch goroutine races on its own published fields

`pkg/resmgr/cache/pod.go:144-168`:

```go
func (p *pod) goFetchPodResources(ch <-chan *podresapi.PodResources) {
	go func() {
		if ch != nil {
			p.podResCh = ch
			p.waitResCh = make(chan struct{})   // written inside goroutine
			defer close(p.waitResCh)
			p.PodResources = <-ch
			...
		}
	}()
}

func (p *pod) GetPodResources() *podresapi.PodResources {
	if p.waitResCh != nil {                     // read from another goroutine
		<-p.waitResCh
	}
	return p.PodResources
}
```

`p.waitResCh` is assigned *inside* the spawned goroutine but read by
`GetPodResources` from the caller's goroutine, with no synchronization. The
happens-before relationship the code depends on does not exist:

- If `GetPodResources` runs before the goroutine reaches line 148, it observes
  `waitResCh == nil`, skips the wait entirely, and returns `p.PodResources`
  before the fetch has completed — silently losing pod resources rather than
  waiting for them. This is the intended-behaviour failure, and it is a plain
  data race on both `waitResCh` and `PodResources`.
- `setPodResources` (line 157) writes `p.PodResources` from the resync path with
  no coordination against the in-flight goroutine writing the same field.

The channel must be created **synchronously in `goFetchPodResources` before the
`go` statement**, which is the standard fix and restores the intended ordering.
The race on `PodResources` itself needs the field guarded or the write confined
to the goroutine.

Because `-race` is enabled in debug builds (`Makefile:122`), this is likely to be
caught by e2e tests once exercised concurrently — it has probably been masked by
the resmgr lock serializing the *callers*, which does not help since the racing
write is in an unsynchronized goroutine.

### <a id="f7"></a>F7. Deferred close errors are silently discarded

Five functions use the "capture close error into `err`" idiom but declare an
**unnamed** result, so the assignment writes to a local that is discarded at
return. `pkg/cgroups/cgroupcontrol.go:156` is representative:

```go
func (g Group) Write(entry, format string, args ...interface{}) error {
	f, err := os.OpenFile(entryPath, os.O_WRONLY, 0644)
	...
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr            // assigns to the local; return value already set
		}
	}()
	...
	return nil                    // always nil regardless of close outcome
}
```

Affected sites:

| Location | Function |
|----------|----------|
| `pkg/cgroups/cgroupcontrol.go:156` | `Group.Write` |
| `pkg/cgroups/cgroupcontrol.go:200` | `Group.writePids` |
| `pkg/resmgr/cache/cache.go:1319` | `cache.WriteFile` |
| `cmd/config-manager/main.go:122` | `configureNriForCrio` |
| `cmd/config-manager/main.go:147` | `writeToContainerdConfig` |

`pkg/sysfs/utils.go:149` (`writeSysfsRaw`) has the same idiom but **correctly**
declares `(err error)` — it is the model the others should follow.

This matters more than usual here: these functions write to cgroup control files
and to the CRI-O configuration drop-in. For buffered writes to a cgroup pseudo-file
the kernel commonly reports rejection (`EINVAL` for an out-of-range value,
`ENOSPC`, `EBUSY`) at **close** time, not at write time. So the specific errors
that indicate "the resource limit you asked for was refused" are exactly the ones
being dropped, and the caller sees success.

### <a id="f8"></a>F8. Health checks run under a global lock

`pkg/healthz/healthz.go:89-109`:

```go
func check() (Status, map[string]error) {
	lock.Lock()
	defer lock.Unlock()

	for _, name := range sorted {
		if s, err := checkers[name](); s != Healthy {   // arbitrary callback
```

Registered `CheckFn` callbacks are invoked while the package-global `lock` is
held. `check()` is called from the `/healthz` HTTP handler, so:

- A checker that blocks (an I/O read, a syscall, an RPC) blocks every other
  concurrent `/healthz` request and any concurrent `RegisterHealthChecker`.
- A checker that calls `RegisterHealthChecker`, directly or transitively,
  self-deadlocks on a non-reentrant `sync.Mutex`.

The lock is only needed to read `sorted` and snapshot the map. Copy the checker
list under the lock, release it, then invoke the callbacks. The
`panic` on duplicate registration (line 80) is a separate style concern — a
library returning an error would be preferable to crashing the plugin — though it
is at least init-time and fail-fast.

### <a id="f9"></a>F9. Metrics callback iterates the balloon slice unlocked

`cmd/plugins/balloons/policy/metrics.go:105-116`:

```go
_, err = m.meter.RegisterCallback(
	func(ctx context.Context, o metric.Observer) error {
		for _, bln := range b.balloons {     // unsynchronized read
			...
			m.Observe(o, bln)               // takes the lock, per element
```

`m.Observe` correctly acquires `meterLock` (line 124) — but only *after* the
range expression has already read `b.balloons`. The slice header is read with no
lock at all, and the allocation paths that mutate it hold the lock via
`BlockMeters`/`UnblockMeters` (`balloons-policy.go:254, 278, 332, 366, 1526`).

Note the lock's polarity is inverted from the usual convention:
`BlockMeters` takes `RLock` (the allocation side, several concurrent allocators
tolerated) and `RequestMeters` takes the exclusive `Lock` (the metrics side).
That is a deliberate and defensible choice, but it means the metrics callback is
the *writer* and must hold the exclusive lock across the entire iteration — not
re-acquire it per element.

As written there are two bugs: a data race on the slice header against balloon
creation/deletion, and a torn view — the lock is dropped between elements, so a
single scrape can observe balloons from several different policy states and
report an internally inconsistent snapshot.

The lock should be acquired once around the whole loop, with `Observe` changed to
assume it is held (or split into a locked wrapper and an unlocked core).

### <a id="f10"></a>F10. `RefreshPods` serializes the whole cache once per pod

`pkg/resmgr/cache/cache.go:738-763` calls `InsertPod` and `DeletePod` in loops.
Both call `cch.Save()` unconditionally (lines 643 and 699), and `Save` →
`Snapshot` marshals **every pod, every container, and all policy data** to JSON
and rewrites the cache file (lines 1142-1251).

For a resync discovering *N* new pods and purging *M* stale ones, that is
*N + M* full serializations and *N + M* file rewrites where one would do. On a
node with hundreds of pods this is quadratic in the pod count, and it happens on
the startup path — exactly when the plugin is trying to converge quickly.

The infrastructure to fix this already exists and is unused here:
`BlockSave`/`UnblockSave` (lines 1212-1226) implement a save-suppression counter
for precisely this purpose. Wrapping the `RefreshPods` body in
`BlockSave()` / `defer UnblockSave()` collapses it to a single save.

Two related observations on that mechanism: `saveBlock` is a plain `int` mutated
without synchronization (harmless only because of the external resmgr lock — see
F5), and `UnblockSave` correctly self-heals a negative counter, which suggests
prior trouble with unbalanced calls. A `defer`-based wrapper avoids that class of
bug.

### <a id="f11"></a>F11. Debug logging formats unconditionally

`pkg/log/slog.go:91-93`:

```go
func (l *slogger) Debugf(format string, args ...any) {
	l.Log(LevelDebug, fmt.Sprintf(format, args...))
}
```

`fmt.Sprintf` runs before the level check inside `Log`. Every `Debugf` call pays
full formatting cost — reflection over each argument, string allocation — even
when debug logging is off, which is the default in production. The same applies
to `Infof`, `Warnf`, `Errorf`, and `LogBlock` (line 122, which additionally
splits the formatted result on newlines and allocates a slice).

Scale, measured across the non-test tree:

- 557 `Debugf`/`Tracef` call sites total
- 369 of them in the hot paths: `pkg/resmgr/cache`, `pkg/cpuallocator`,
  `pkg/resmgr/lib/memory`, and both policies
- only 15 sites guard with `DebugEnabled()`
- 13 use `%+v` on structs, the most expensive case — reflection over an entire
  struct graph. `pkg/resmgr/cache/pod.go:152` formats a whole
  `*podresapi.PodResources` on every pod-resource fetch.

Beyond the per-call cost, the arguments are *evaluated* at the call site
regardless. Calls like `a.Debugf(" => idle packages sorted by preference: %v",
pkgs)` in the CPU allocator (`allocator.go:215`) and the `PrettyPrint()`-style
helpers force real work for output that is then discarded.

`DebugEnabled()` already exists (line 168) and `cfg.Debugging(l.source)` is the
check `Log` performs anyway. An early return in the `*f` methods fixes every call
site at once without touching callers — the single highest-leverage change in
this audit.

---

## Low severity

### <a id="f12"></a>F12. Swapped format arguments in a validation error

`pkg/apis/resmgr/v1alpha1/expression.go:77-80`:

```go
if restKey != "" {
	return exprError("invalid expression, trailing key %q after %q",
		prefKey, restKey)
}
```

The message says "trailing key X after Y" but passes `prefKey` (the *prefix*) as
the trailing key and `restKey` (the *trailing* part) as what it follows. The
arguments are exactly reversed: for input `"name/extra"` this reports
`trailing key "name" after "extra"` instead of `trailing key "extra" after
"name"`. User-facing config-validation message, actively misleading while
debugging a bad expression.

### <a id="f13"></a>F13. `readPids` reports the wrong error variable

`pkg/cgroups/cgroupcontrol.go:192-194`:

```go
if s.Err() != nil {
	return nil, g.errorf("failed to read %q: %v", entry, err)
}
```

The condition tests the scanner error `s.Err()` but the message formats `err` —
the `os.OpenFile` error from line 182, which is necessarily `nil` at this point
(the function returned early otherwise). A genuine read failure is reported as
`failed to read "tasks": %!v(<nil>)`, discarding the actual cause.

### <a id="f14"></a>F14. Tar extraction lacks a path-traversal guard

`pkg/testutils/tar.go` joins `header.Name` straight onto the destination for all
three handled entry types (lines 47, 53, 65) with no check that the result stays
within `dir`. An archive containing `../../etc/foo` writes outside the target;
`tar.TypeSymlink` (line 69) creates symlinks from unvalidated `header.Linkname`
with no containment check at all, the classic "symlink then write through it"
escape.

This is the `Zip Slip` pattern. Severity is **low, not high**, because the
package is test-only, the file documents that (`must not be used in production
code`, line 26), and the inputs are checked-in fixtures rather than untrusted
data. It is worth fixing anyway: the guard is three lines, and the current code
is a ready-made copy-paste source for someone who does need extraction in a
non-test context.

### <a id="f15"></a>F15. Error-string convention violations

Go convention (and `staticcheck ST1005`) is that error strings start lowercase,
since they are routinely wrapped and appear mid-sentence. Roughly 20 sites start
with a capital, mostly where the leading token is a legitimate proper noun or
identifier and the fix is to reword rather than to lowercase:

- `pkg/utils/parse.go:30` — `"ParseEnabled: invalid string %q"`; a function name
  in its own error message, redundant with the wrap chain
- `pkg/pidfile/pidfile.go:141` — `"FindProcess() failed for PID %d"`
- `pkg/agent/podresapi/client.go:49` — `"PodResources API Get method disabled"`
- `pkg/resmgr/cpuclass/internal/pct/pct_sst_goresctrl.go` — ~10 sites (`"SST init
  failed"`, `"CPReset on package %d"`, …)
- `cmd/plugins/resctrl-mon/plugin.go:452-463`, `cmd/config-manager/main.go:213-228`

No error strings end in punctuation — that half of the convention is clean.

Related: 130 sites use `fmt.Errorf(... %v", err)` where `%w` would preserve the
chain for `errors.Is`/`errors.As`. Several packages already use `%w` correctly
(`pkg/sysfs`, parts of `cmd/plugins/memtierd`), so the codebase is mid-migration.
This blocks callers from matching on sentinel errors and is worth finishing,
though mechanically and with care — converting `%v` to `%w` widens a function's
API contract, since callers gain the ability to depend on the wrapped type.

### <a id="f16"></a>F16. Dated idioms

Minor modernization, no behavioural impact. Worth doing opportunistically rather
than as a dedicated sweep — a mass rewrite churns history for no functional gain.

- **`interface{}` over `any`** — 104 occurrences in non-test code. `any` has been
  available since Go 1.18; this module requires 1.26 (`go.mod:3`).
- **`sort` over `slices`** — 18 files import `sort`, using `sort.Slice`/`sort.Strings`
  where `slices.SortFunc`/`slices.Sort` are now idiomatic, type-safe, and faster
  (no reflection-based swapping). Note `sort.Slice` is *not* stable; any site
  relying on incidental stability needs `slices.SortStableFunc`, so this is not a
  blind substitution.
- **`ioutil`** — one remaining use, `ioutil.Discard` at
  `pkg/apis/config/v1alpha1/log/klogcontrol/gen-config.go:33`. Deprecated since
  Go 1.16; replace with `io.Discard`.
- **`panic` in library code** — 14 non-test sites. Most are defensible
  (`pkg/log/slog.go:88` implements `Panic`; `pkg/cgroups/cgroupid_other.go:7` is a
  non-Linux stub). Two are worth revisiting: `pkg/utils/cpuset/cpuset.go:37`
  panics on a parse failure, and `pkg/kubernetes/resources.go:193,208` panic on
  invalid capacity — both convert recoverable input errors into a plugin crash.

## What was checked and found clean

Recording the negative results, since they bound the audit's coverage:

- **`pkg/agent/node-extended-resources.go`** — the timer-drain idiom at lines
  114-134 is correct, including the subtle `if !timer.Stop() { drain }` sequence.
  Well-commented single-writer design.
- **`cmd/plugins/memtierd`** — has been security-hardened already:
  `sanitizePathSegment` rejects `..`, `/`, and NUL; `ensureSecureDir` refuses
  symlinks and chmods explicitly to defeat umask; `writeFileAtomic` uses
  `O_EXCL|O_NOFOLLOW` plus rename. This is the standard the other file-writing
  code should be held to.
- **No use of `math/rand`** anywhere — no weak-randomness findings.
- **Timer/ticker leaks** — both `time.NewTicker`/`NewTimer` sites have a
  matching `defer Stop()`. The one `time.After` (`pkg/agent/watch/object.go:181`)
  is guarded against re-arming and is bounded.
- **`unsafe`** — confined to the three `pkg/mempolicy` syscall sites (F1/F2). No
  other use in the tree.
- **`exec.Command`** — two sites, neither building a command from untrusted
  input. `cmd/plugins/memtierd/main.go:543` passes a fixed argv;
  `cmd/mpolset/mpolset.go:160` uses `syscall.Exec` on a `LookPath` result.
- **Error strings ending in punctuation** — none.
- **`defer` inside a loop** — no instances in non-test code.

## Next steps

See [`plan.md`](plan.md) for sequenced remediation, grouped into independently
landable phases with test strategy per fix.

---

## <a id="addendum"></a>Addendum: re-review of `accbbd38..12d21229`

Five commits landed on `main` after the initial audit. All were reviewed; the
findings below are the delta. Verification limits are unchanged — no analyzer or
compiler ran (`gofmt -l` on the changed files is clean, which is the only
tool-backed check that was possible).

| Commit | Assessment |
|--------|------------|
| `c17a6b31` cpuclass: hint all good CPU sets | Sound. Type change propagated consistently; disjointness invariant holds. Surfaces pre-existing [F19](#f19) in the consumer. |
| `8dcd1613` resmgr: force cache save after CreateContainer | Correct, and validates the [F10](#f10) recommendation. See note below. |
| `37a01cac` config-manager: don't panic on empty config.toml | Correct minimal fix. |
| `12d21229` agent: clear own config status on stop | Introduces [F17](#f17). |
| `06eb4f46` e2e: force RPM installation | Test infrastructure only; no product impact. |

### <a id="f17"></a>F17. `clearOwnConfigStatus` blocks the signal path and races on `currentCfg`

`pkg/agent/agent.go:267-274` now calls `clearOwnConfigStatus()` from `Stop()`:

```go
func (a *Agent) Stop() {
	a.stopLock.Lock()
	defer a.stopLock.Unlock()

	if a.stopC != nil {
		a.clearOwnConfigStatus()   // added: blocking API call, up to 10s
		close(a.stopC)             // event loop is still running until here
		<-a.doneC
		a.stopC = nil
	}
}
```

Two problems, both created by the ordering:

**A data race on `a.currentCfg`.** `clearOwnConfigStatus` reads `a.currentCfg`
(line 641 and 649) *before* `close(a.stopC)`, so the event loop in `Start()` is
still running. That loop writes `a.currentCfg` from `updateConfig` (lines 618 and
634) with no lock — `stopLock` guards only the stop channel, and the two paths
share no mutex. `Stop()` runs on the signal-handler goroutine
(`pkg/resmgr/main/main.go:78-87`) while `Start()` runs on the main goroutine, so
these are genuinely concurrent. A config update arriving during shutdown is an
unsynchronized read/write of an interface value: the reader can observe a torn
`metav1.Object` (type and data words from different assignments), which makes the
subsequent `GetName()` call unsafe rather than merely stale.

This is the same class as [F5](#f5) — the cache relies on an external lock — but
here there is no external lock covering both sides.

**A blocking API call added to the shutdown path.** The `PatchStatus` call can take
up to the full 10-second timeout. Until it returns, `stopC` is not closed, so the
event loop and the extended-resources reconciler keep running, and any concurrent
`Stop()` caller blocks on `stopLock`. On SIGTERM the kubelet's grace period is
finite; a slow or unreachable API server can consume it here and the process gets
SIGKILLed — losing the very cleanup this commit adds, and also the extended-resource
cleanup. Note the predecessor commit deliberately *removed*
`ClearNodeExtendedResources()` from this same spot, which suggests the pattern had
already caused trouble.

Recommended fix: close `stopC` and drain the event loop *first*, then perform the
cleanup patch once nothing else can touch `currentCfg`:

```go
func (a *Agent) Stop() {
	a.stopLock.Lock()
	defer a.stopLock.Unlock()

	if a.stopC != nil {
		close(a.stopC)
		<-a.doneC          // event loop has returned; currentCfg is now stable
		a.stopC = nil
		a.clearOwnConfigStatus()
	}
}
```

That removes the race without a new mutex, because after `<-a.doneC` there is no
concurrent writer. It does not fix the grace-period exposure; if that matters, the
timeout should be reduced or derived from a shutdown deadline. **This reordering
depends on [F18](#f18) being fixed first** — as written, `<-a.doneC` never returns.

The merge-patch semantics are correct: `NodeStatusPatch(node, nil)` marshals
`{"status":{"nodes":{"<node>":null}}}` and `types.MergePatchType` deletes the key,
which is what the commit intends. The guard conditions (`cfgIf == nil`,
`nodeName == ""`, `hasLocalConfig()`, `currentCfg == nil`) are appropriate.

### <a id="f18"></a>F18. `Agent.doneC` is never initialized, so `Stop()` blocks forever

Pre-existing, but F17's fix depends on it and the new commit makes `Stop()` do
more work before reaching it. `pkg/agent/agent.go:154` declares:

```go
stopLock sync.Mutex
stopC    chan struct{}
doneC    chan struct{}
```

`New()` initializes `stopC` (line 171) but **not** `doneC`, and nothing anywhere
in the package ever assigns to or closes `Agent.doneC` — the only two references
in the file are the declaration and the receive at line 272. A receive from a nil
channel blocks forever, so `Stop()` deadlocks after closing `stopC`, permanently
holding `stopLock`.

This is the same defect class as [F4](#f4) (`pkg/http`): a `chan struct{}` field
that is declared, waited on, and never created. It survived because the process is
exiting anyway — `Start()`'s loop does return on `stopC`, so the shutdown
*appears* to work while `Stop()` itself never returns. The signal handler
goroutine simply leaks until the process dies, which on SIGTERM it soon does.

Two consequences worth noting:

- Any cleanup placed *after* `<-a.doneC` is dead code. That is precisely where
  F17's fix wants to put `clearOwnConfigStatus()`.
- `a.stopC = nil` never executes, so `Stop()` is not idempotent in the way the
  `if a.stopC != nil` guard implies; a second caller blocks on `stopLock` instead
  of returning.

Fix: create `doneC` in `New()` and close it when the event loop returns.

```go
// in New():
doneC: make(chan struct{}),

// in Start(), around the event loop:
defer close(a.doneC)
```

`Start()` returns from several error paths before the loop begins, so `defer
close(a.doneC)` should be installed only once the loop is guaranteed to run —
otherwise a setup failure closes `doneC` and a later `Stop()` returns without the
loop ever having started. Placing it immediately before `for {` is correct.
`errcheck` will not catch this class; `go vet` does not either. A unit test that
calls `Start` in a goroutine and asserts `Stop()` returns within a timeout would.

### <a id="f19"></a>F19. Hint consumer panics on unexpected `delta` and overflows past 64 hint devices

`c17a6b31` changes `CpuPreference.Cpus` from one `cpuset.CPUSet` to a
priority-ordered `[]cpuset.CPUSet`, so a single class hint can now contribute
several candidate sets. The refactor itself is correct — Tier A candidates are
per-punit and Tier B candidates are per-package, tiers are never mixed, and both
partitions are disjoint, so the "honor the first feasible candidate" contract the
new doc comment states does hold. Two pre-existing weaknesses in the *consumer*
become easier to reach now that the hint lists are longer.

**Unguarded index in the shrink path.** `cmd/plugins/balloons/policy/cputree.go:723`:

```go
maxHints := currentCpuHints[leastHintedCpus[-delta]]
```

`leastHintedCpus` has `currentCpus.Size()` elements, so this panics when
`-delta >= currentCpus.Size()`. `resizeCpusOnlyIfNecessary`
(`cputree.go:603-609`) does return early for both `currentCpus.Size() < -delta`
and `== -delta`, so the index is in range on the normal path — this is a latent
invariant, not a live crash. It is worth an explicit guard rather than a
cross-function argument, because the entry condition lives four resizers away
from the indexing and nothing local documents it.

**Hint priority weights overflow.** `cputree.go:715`:

```go
currentCpuHints[cpu] += 1 << (len(allCloseCpuSets) - 1 - hintPriority)
```

The weight is exponential in the number of hint devices. `currentCpuHints` is
`map[int]uint64`, so with more than 64 entries in `allCloseCpuSets` the shift
exceeds the width of the type: `hintPriority` values past 63 shift by a negative
amount, which for an unsigned shift count in Go wraps to a huge value and yields
0, silently collapsing the priority ordering. Reaching 64 requires an unusual
configuration (`preferCloseToDevices` plus `preferFarFromDevices` plus per-class
hints), so this is a robustness issue rather than a likely one. A rank-based
comparison — sort by `(hintPriority, ...)` instead of summing powers of two —
removes the ceiling entirely.

Neither defect is introduced by `c17a6b31`; both predate it. Flagged here because
the commit increases the number of candidate sets flowing into this code, and
because a follow-up that pushes cpuclass hints for many devices would meet them.

### Correction to F10

[F10](#f10) recommended wrapping bulk cache mutations in
`BlockSave()`/`defer UnblockSave()`. `8dcd1613` applies exactly that pattern to
`CreateContainer` (`pkg/resmgr/nri.go:456-461`), joining the existing use in
`syncWithNRI` (line 237). The finding's claim stands as written — it says the
mechanism is unused *in `RefreshPods`*, which remains true — but note the
mechanism now has two production callers, so the plan's step is a third use of an
established pattern rather than the first.

That commit's own purpose is worth recording: it forces a save so a container's
`Created` state reaches disk, because leaving the last container in the synthetic
`Creating` state made it invisible to startup recovery. `BlockSave`/`UnblockSave`
is doing double duty here — coalescing writes *and* guaranteeing a write happens
at scope exit. Any change to `RefreshPods` should preserve the second property.

### Correction to F7

The F7 table listed four unnamed-return sites; an exhaustive sweep of the tree
finds **five**. `cmd/config-manager/main.go:147` (`writeToContainerdConfig`) was
missed. It is the worst of the set in one respect: the function ends with
`return w.Flush()`, and the deferred `f.Close()` runs after that return value is
already fixed, so a failed flush-to-disk *and* a failed close are both invisible
to the caller — while writing the containerd configuration that enables NRI.

The same file's `writeConfig` sibling shows the fix is understood locally; only the
result declaration is missing. The table above has been corrected.

Also worth noting for Phase 0 of the plan: `errcheck` would not have flagged any of
these five, since the errors *are* assigned. This class needs either `staticcheck`
(which reports the ineffective assignment) or review.

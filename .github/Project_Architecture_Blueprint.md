# NRI Plugins — Project Architecture Blueprint

> Generated: 2026-06-15  
> Purpose: Definitive architectural reference for maintaining consistency and guiding new development.  
> Update this document when architectural boundaries, interfaces, or patterns change significantly.

---

## Table of Contents

1. [Architectural Overview](#1-architectural-overview)
2. [Architecture Visualization](#2-architecture-visualization)
3. [Core Architectural Components](#3-core-architectural-components)
4. [Architectural Layers and Dependencies](#4-architectural-layers-and-dependencies)
5. [Data Architecture](#5-data-architecture)
6. [Cross-Cutting Concerns](#6-cross-cutting-concerns)
7. [Configuration Management](#7-configuration-management)
8. [Service Communication Patterns](#8-service-communication-patterns)
9. [Technology-Specific Patterns](#9-technology-specific-patterns)
10. [Testing Architecture](#10-testing-architecture)
11. [Deployment Architecture](#11-deployment-architecture)
12. [Extension and Evolution Patterns](#12-extension-and-evolution-patterns)
13. [Architectural Decision Records](#13-architectural-decision-records)
14. [Architecture Governance](#14-architecture-governance)
15. [Blueprint for New Development](#15-blueprint-for-new-development)

---

## 1. Architectural Overview

### Project Purpose

NRI Plugins is a collection of [Node Resource Interface (NRI)](https://github.com/containerd/nri) plugins for Kubernetes. Each plugin intercepts container lifecycle events from a container runtime (containerd, CRI-O) and applies hardware resource policies — CPU topology affinity, memory NUMA placement, CPU frequency scaling, SGX EPC allocation, etc. — without modifying the runtime itself.

### Guiding Principles

| Principle | Expression in Code |
|-----------|-------------------|
| **Plugin isolation** | Each policy compiles to its own binary; `cmd/plugins/<name>/` |
| **Policy as a plugin** | All resource management policies implement the same `policy.Backend` interface |
| **Separation of concerns** | NRI integration, policy logic, cache, and system abstraction are independent packages |
| **CRD-driven configuration** | Per-plugin Kubernetes CRDs replace static config files; live updates via the agent |
| **Hardware abstraction** | `pkg/sysfs` and `pkg/topology` provide a typed, testable view of NUMA/CPU/memory topology |
| **Observability first** | OpenTelemetry tracing + Prometheus metrics are wired in at the framework level |

### Architectural Pattern

The project follows a **Plugin Host + Strategy** pattern layered over a **Hexagonal (Ports & Adapters)** structure:

- The **host** (`pkg/resmgr`) owns the NRI connection, the container cache, and lifecycle orchestration.
- The **strategy** (`policy.Backend` interface) is swapped per binary; each plugin supplies one policy implementation.
- **Adapters** at the edges: NRI stub (inbound), Kubernetes agent (inbound config), sysfs (outbound HW reads), cgroup/CPU controllers (outbound HW writes).

---

## 2. Architecture Visualization

### High-Level System Context

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Kubernetes Node                                │
│                                                                      │
│  ┌────────────────┐    NRI socket    ┌────────────────────────────┐  │
│  │ Container      │◄────────────────►│  NRI Plugin binary         │  │
│  │ Runtime        │  (ttrpc/gRPC)    │  (nri-resource-policy-*    │  │
│  │ (containerd /  │                  │   nri-memory-*, etc.)      │  │
│  │  CRI-O)        │                  └──────────┬─────────────────┘  │
│  └────────────────┘                             │                    │
│                                                 │                    │
│  ┌─────────────────────────────────────────┐    │                    │
│  │  Kubernetes API Server                  │    │                    │
│  │  (CRD: TopologyAwarePolicy,             │◄───┘ (watch CRDs)      │
│  │   BalloonsPolicy, etc.)                 │                        │
│  └─────────────────────────────────────────┘                        │
│                                                                      │
│  ┌─────────────────────────────────────────┐                        │
│  │  Linux Kernel / Hardware                │                        │
│  │  /sys/fs/cgroup, /sys/bus/cpu, NUMA     │◄─── cgroup writes      │
│  └─────────────────────────────────────────┘     sysfs reads        │
└──────────────────────────────────────────────────────────────────────┘
```

### Component Interaction Diagram

```
cmd/plugins/<name>/main.go
        │
        │ creates
        ▼
pkg/resmgr/main  ──────────────────────── pkg/agent
  Main{policy, mgr, agt}                    │
        │                                   │ watches K8s CRDs
        │ creates                           │ delivers config
        ▼                                   │
pkg/resmgr                                  │
  ResourceManager ◄──────────────────────── ┘
        │
        ├─── nriPlugin  (pkg/resmgr/nri.go)
        │       │ containerd/nri stub
        │       │ container lifecycle events
        │       ▼
        │    NRI Runtime
        │
        ├─── policy.Backend  (pkg/resmgr/policy)
        │       │ implemented by each plugin
        │       ▼
        │    cmd/plugins/<name>/policy/
        │       │
        │       ├── pkg/resmgr/cache   (container state)
        │       ├── pkg/sysfs          (hardware topology)
        │       ├── pkg/cpuallocator   (CPU allocation)
        │       └── pkg/resmgr/lib/memory (memory allocation)
        │
        ├─── control layer  (pkg/resmgr/control/)
        │       └── cpu controller, RDT, BlockIO
        │
        └─── instrumentation  (pkg/instrumentation)
                ├── OpenTelemetry traces + metrics
                └── Prometheus HTTP endpoint
```

### Data Flow: Container Lifecycle

```
Container Runtime
    │ RunPodSandbox / CreateContainer / StartContainer
    ▼
nriPlugin.{RunPodSandbox,CreateContainer,StartContainer}()
    │ wraps into cache.Container
    ▼
cache.Cache  ──► topology hints, pod annotations
    │
    ▼
policy.Backend.AllocateResources(container)
    │ policy decision (CPU set, memory nodes, etc.)
    ▼
cache.Container.SetCPUSet() / SetMemoryLimit()
    │
    ▼
nriPlugin applies changes back to runtime via NRI response
    │
    ▼
control.CPU / cgroup writes (out-of-band enforcement)
```

---

## 3. Core Architectural Components

### 3.1 `pkg/resmgr` — Resource Manager Host

**Purpose:** The central orchestrator. Owns the NRI plugin stub, the container cache, and coordinates between the NRI event stream, the policy backend, and the configuration agent.

**Key types:**
- `ResourceManager` (interface) — Start/Stop/SendEvent
- `resmgr` (private struct) — concrete implementation
- `nriPlugin` — wraps `containerd/nri/pkg/stub.Stub`, receives all lifecycle hooks

**Interaction pattern:** Lifecycle events arrive from NRI, are translated into `cache.Container` objects, forwarded to `policy.Backend`, and the resulting resource assignments are written back as NRI responses and optionally enforced via the `control` layer.

---

### 3.2 `pkg/resmgr/policy` — Policy Backend Interface

**Purpose:** The strategy interface that all resource management policies implement. Defines the contract between the framework and any policy logic.

```go
type Backend interface {
    Name() string
    Description() string
    Setup(*BackendOptions) error
    Reconfigure(interface{}) error
    Start() error
    Sync(add, del []cache.Container) error
    AllocateResources(cache.Container) error
    ReleaseResources(cache.Container) error
    UpdateResources(cache.Container) error
    HandleEvent(*events.Policy) (bool, error)
    ExportResourceData(cache.Container) map[string]string
    GetTopologyZones() []*TopologyZone
}
```

**`BackendOptions`** supplies the policy with everything it needs at setup time:
- `System system.System` — NUMA/CPU/memory topology
- `Cache cache.Cache` — live container state
- `SendEvent SendEventFn` — callback to send policy events upward
- `Config interface{}` — policy-specific config struct

---

### 3.3 `cmd/plugins/<name>/policy/` — Policy Implementations

Each sub-directory under `cmd/plugins/` contains one policy implementation:

| Plugin Binary | Policy Directory | Resource Domain |
|---------------|-----------------|----------------|
| `nri-resource-policy-topology-aware` | `topology-aware/policy/` | CPU + Memory NUMA topology |
| `nri-resource-policy-balloons` | `balloons/policy/` | CPU pools ("balloons") |
| `nri-resource-policy-template` | `template/policy/` | No-op template for new policies |
| `nri-memory-policy` | `memory-policy/policy/` | Memory NUMA placement |
| `nri-memory-qos` | `memory-qos/` | Memory QoS cgroup settings |
| `nri-memtierd` | `memtierd/` | Memory tiering via memtierd |
| `nri-sgx-epc` | `sgx-epc/` | Intel SGX EPC memory |
| `nri-resctrl-mon` | `resctrl-mon/` | Intel RDT monitoring |

**Pattern:** Each policy struct embeds `*policy.BackendOptions`, holds its own config type, and satisfies `policy.Backend`. A `New()` function returns the `policy.Backend` interface, keeping concrete types private.

---

### 3.4 `pkg/resmgr/cache` — Container State Cache

**Purpose:** A write-through cache of all pods and containers known to the resource manager. Stores resource assignments, pod annotations, topology hints, and pending changes per enforcement domain (`CPU`, `NRI`).

**Key interfaces:**
- `Cache` — top-level CRUD for pods/containers; snapshot/restore
- `Container` — per-container resource state (CPUSet, memory limits, RDT class, BlockIO class)
- `Pod` — aggregates containers; exposes Kubernetes pod metadata and annotations

The cache is the **shared state** between the policy and the NRI layer. Policies write resource decisions into the cache; the NRI plugin reads them back to build NRI update responses.

---

### 3.5 `pkg/agent` — Kubernetes Configuration Agent

**Purpose:** Connects to the Kubernetes API server to watch per-plugin CRD objects. When a matching `BalloonsPolicy` / `TopologyAwarePolicy` / … CRD changes, the agent delivers the new config to the resource manager which forwards it to `policy.Backend.Reconfigure()`.

**Abstractions:**
- `ConfigInterface` — per-plugin interface exposing the CRD Group/Version/Kind and deserialization
- `Agent.New()` takes a `ConfigInterface`; different plugins pass different implementations via `agent.BalloonsConfigInterface()` / `agent.TopologyAwareConfigInterface()`
- Supports both CRD-based watching and file-based config (for testing/standalone use)

---

### 3.6 `pkg/apis/config/v1alpha1` — CRD API Types

**Purpose:** Kubernetes CRD type definitions for all per-plugin configurations. Generated code (`zz_generated.deepcopy.go`) lives alongside hand-written types.

**Three-file pattern per policy:**
1. `types.go` — CRD structs (`BalloonsPolicy`, `TopologyAwarePolicy`, etc.) with `+kubebuilder:object:root=true` markers
2. `<name>-policy.go` — implements `ResmgrConfig` interface; compile-time check: `var _ ResmgrConfig = &BalloonsPolicy{}`
3. `resmgr/policy/<name>/config.go` — policy-specific `Config` struct embedded in the CRD spec

**`ResmgrConfig` interface** (in `resmgr.go`):
```go
type ResmgrConfig interface {
    metav1.ObjectMetaAccessor
    AgentConfig() *AgentConfig
    CommonConfig() *CommonConfig
    PolicyConfig() interface{}
}
```

---

### 3.7 `pkg/sysfs` — Hardware Topology Abstraction

**Purpose:** Typed, testable interface over Linux `sysfs` for discovering CPU topology, NUMA nodes, memory, cache hierarchy, and I/O devices.

**Key interface:** `System` — root of the hardware model
- `Nodes()` → NUMA nodes with CPU/memory/distance info
- `CPUs()` → individual CPU cores with package/die/core/thread IDs
- `PackageCount()`, `NUMANodeCount()` etc.

**`utils.go`** (recently refactored): Typed generic read/write functions eliminate unsafe integer casts:
- `readSysfsEntry[T constraints.Integer](path string) (T, error)` — uses `reflect.TypeOf(*new(T)).Size()*8` for correct bit-width dispatch
- `parseIDSet(s, sep string) (idset.IDSet, error)` — supports both space-separated and comma-separated range lists (e.g. `"0-7,15-23"`)

---

### 3.8 `pkg/instrumentation` — Observability

**Purpose:** Unified entry point for OpenTelemetry tracing (OTLP gRPC/HTTP export) and Prometheus metrics. Exposes an HTTP server for `/metrics` and health endpoints.

Sub-packages:
- `tracing/` — span creation helpers; wraps `go.opentelemetry.io/otel/trace`
- `metrics/` — counter/gauge/histogram registration
- `pkg/metrics/` — Prometheus integration via `prometheus/client_golang`

Configuration is live-reloadable via the CRD `instrumentation.Config` sub-struct embedded in every policy CRD spec.

---

### 3.9 `pkg/resmgr/control` — Hardware Control Layer

**Purpose:** Applies resource assignments to the kernel *out-of-band* (outside the NRI response cycle). Handles CPU frequency scaling, C-states, RDT (Resource Director Technology), and BlockIO class assignment.

`control/cpu/` manages:
- CPU class assignment to cpusets (persisted in the cache)
- C-state overrides via `OVERRIDE_SYS_CSTATES` environment variable (JSON overlay for testing)
- CPU frequency policy via Intel Speed Select Technology (`intel_pstate`)

---

### 3.10 `pkg/resmgr/lib/memory` — Memory Allocator Library

**Purpose:** A NUMA-aware memory allocator used by topology-aware and balloons policies. Models NUMA nodes as a weighted graph; allocates memory using configurable affinity and fallback strategies.

Key types: `Allocator`, `Request` (with `Affinity`, `Types`, `Limit`), `Zone` (NUMA node set).

---

## 4. Architectural Layers and Dependencies

```
┌──────────────────────────────────────────────────────────┐
│  Layer 0: Entry Points                                   │
│  cmd/plugins/<name>/main.go                              │
│  cmd/config-manager/, cmd/resource-annotator/            │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│  Layer 1: Framework (pkg/resmgr/main, pkg/resmgr)        │
│  Resource manager lifecycle; NRI stub management         │
│  MUST NOT depend on any specific policy package          │
└──────┬──────────────┬──────────────────────┬─────────────┘
       │              │                      │
┌──────▼──────┐ ┌─────▼──────┐  ┌───────────▼──────────────┐
│ Layer 2a:   │ │ Layer 2b:  │  │ Layer 2c:                │
│ Policy      │ │ Agent      │  │ Instrumentation           │
│ Interface   │ │ pkg/agent  │  │ pkg/instrumentation       │
│ pkg/resmgr/ │ │            │  │                          │
│ policy      │ └────────────┘  └──────────────────────────┘
└──────┬──────┘
       │
┌──────▼──────────────────────────────────────────────────┐
│  Layer 3: Policy Implementations                        │
│  cmd/plugins/<name>/policy/                             │
│  Depends on: cache, sysfs, cpuallocator, lib/memory     │
└──────┬──────────────────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────────┐
│  Layer 4: Infrastructure / Shared Libraries             │
│  pkg/sysfs, pkg/topology, pkg/cpuallocator,             │
│  pkg/resmgr/lib/memory, pkg/resmgr/cache                │
│  pkg/log, pkg/utils, pkg/kubernetes                     │
└──────┬──────────────────────────────────────────────────┘
       │
┌──────▼──────────────────────────────────────────────────┐
│  Layer 5: External / System                             │
│  Linux sysfs, cgroups, NRI socket, Kubernetes API       │
└─────────────────────────────────────────────────────────┘
```

**Dependency rules:**
- Higher-numbered layers may depend on lower-numbered layers; never the reverse.
- `pkg/resmgr` (Layer 1) depends on `policy.Backend` **interface only**; it never imports a concrete policy.
- Concrete policies (Layer 3) live in `cmd/`, not `pkg/`, to make this layering explicit.
- `pkg/topology` is a **separate Go module** (`pkg/topology/go.mod`); imported as a replace directive.

---

## 5. Data Architecture

### Domain Model

```
System (sysfs)
  └── Package[]
        └── NUMANode[]
              ├── CPU[]  (core, thread, online, isolated)
              ├── Memory (total, free, types: DRAM/PMEM/HBM)
              └── Distance[] (to other NUMA nodes)

Pod (cache)
  ├── metadata (name, namespace, QoS class, annotations)
  └── Container[]
        ├── ResourceRequirements (requests/limits)
        ├── CPUSet (assigned)
        ├── MemoryLimit (per type)
        ├── TopologyHints (from kubelet PodResources API)
        ├── RDTClass
        └── BlockIOClass
```

### Key Annotation Namespace

All pod annotations consumed by NRI plugins use the `resource-policy.nri.io/` namespace prefix (via `pkg/kubernetes.ResmgrKeyNamespace`):

| Annotation | Purpose |
|-----------|---------|
| `balloon.balloons.resource-policy.nri.io` | Assign pod to a named balloon |
| `rdtclass.resource-policy.nri.io` | Override RDT class |
| `topologyhints.resource-policy.nri.io` | Opt out of topology hints |
| `memory-type.resource-policy.nri.io` | Request specific memory types |

### Data Access Patterns

- **Cache as write-through store:** Policies write resource decisions to `cache.Container` setters; the cache serialises state to disk for restart recovery.
- **Snapshot/restore:** The cache supports JSON snapshots for crash recovery.
- **No ORM:** All data access is direct struct field access; no database.

---

## 6. Cross-Cutting Concerns

### 6.1 Logging

`pkg/log` wraps `k8s.io/klog/v2` and `log/slog` with a unified `Logger` interface. Logger instances are module-scoped:

```go
var log = logger.NewLogger("balloons")  // named per-component logger
```

Log levels: Debug, Info, Warn, Error, Fatal, Panic. Level controlled at runtime via `SIGUSR1` toggle or via `log.Config` in the CRD spec.

### 6.2 Error Handling

- All errors are wrapped with context using `fmt.Errorf("... %w", err)`.
- Fatal errors (startup failures) call `log.Fatal` or `log.Fatalf` which invoke `klog.Fatal`.
- Policy methods return `error`; the resource manager decides whether to retry or report.
- No panic-based control flow in production paths.

### 6.3 Metrics and Tracing

Configured via `instrumentation.Config` in each plugin's CRD spec:
- Tracing: OTLP over gRPC (`otlptracegrpc`) or HTTP (`otlpttracehttp`)
- Metrics: Prometheus scrape endpoint on the HTTP server; OTLP metric export also supported
- The `containerd/otelttrpc` interceptor wraps NRI's ttrpc transport for automatic span propagation

### 6.4 Configuration Validation

Each `Config` struct implements a `Validate() error` method. `CommonConfig.Validate()` delegates to sub-configs (`Control.RDT.Validate()`, etc.). Validation runs on every config update delivered by the agent.

### 6.5 Health Checks

`pkg/healthz` exposes a `/healthz` HTTP endpoint; integrated into the shared HTTP server in `pkg/http`.

---

## 7. Configuration Management

### Sources (in priority order)

1. **Kubernetes CRD** — primary in production; watched by `pkg/agent` via the K8s watch API
2. **Config file** — fallback via `--config-file` flag; useful for testing/standalone
3. **Command-line flags** — low-level overrides (NRI socket path, plugin index, log level)

### CRD Update Flow

```
K8s API Server
  │ watch event (Add/Update/Delete)
  ▼
pkg/agent.Agent
  │ deserialises into policy-specific CRD struct
  │ calls ConfigInterface.ResmgrConfig()
  ▼
ResourceManager.SendEvent(config)
  │
  ▼
policy.Backend.Reconfigure(config.PolicyConfig())
```

### Config Namespacing

Each plugin CRD embeds:
- `<Policy>.Config` — policy-specific settings (e.g., `balloons.Config`)
- `control.Config` — RDT + BlockIO class definitions  
- `log.Config` — per-plugin log level overrides  
- `instrumentation.Config` — tracing/metrics endpoints  
- `AgentConfig` — NRT (NodeResourceTopology) CRD publication toggle

---

## 8. Service Communication Patterns

### NRI (Plugin ↔ Runtime)

- **Protocol:** ttrpc (lightweight gRPC over Unix socket)
- **Transport:** Unix domain socket (default: `/var/run/nri/nri.sock`)
- **Pattern:** The runtime initiates; the plugin is a server stub that registers lifecycle hooks
- **Hooks used:** `RunPodSandbox`, `StopPodSandbox`, `RemovePodSandbox`, `CreateContainer`, `PostCreateContainer`, `StartContainer`, `PostStartContainer`, `UpdateContainer`, `StopContainer`, `RemoveContainer`

### Kubernetes API (Agent ↔ API Server)

- **Protocol:** HTTPS (k8s.io/client-go)
- **Pattern:** Watch loop on a specific CRD type per plugin; exponential backoff on errors
- **Auth:** In-cluster service account or `--kubeconfig` flag

### PodResources API (Cache ↔ Kubelet)

- **Protocol:** gRPC Unix socket (`/var/lib/kubelet/pod-resources/kubelet.sock`)
- **Purpose:** Retrieve device topology hints for containers (GPU/FPGA locality)
- Managed by `pkg/agent/podresapi`

### NodeResourceTopology (Agent → K8s)

- `pkg/agent/nrtapi` writes `NodeResourceTopology` CRDs back to the API server so the topology-aware scheduler can consume hardware resource zone data.

---

## 9. Technology-Specific Patterns

### Go-Specific Patterns

**Generics for type-safe sysfs I/O** (`pkg/sysfs/utils.go`):
```go
// readSysfsEntry reads any integer type safely.
func readSysfsEntry[T constraints.Integer](path string) (T, error)

// parseIntTo uses reflect for named-type-aware bit-width detection.
func parseIntTo[T constraints.Integer](s string) (T, error) {
    bits := int(reflect.TypeOf(*new(T)).Size() * 8)
    // parse at detected bit-width, assign to T
}
```

**Interface with compile-time check:**
```go
// In <name>-policy.go — confirms the CRD type implements ResmgrConfig.
var _ ResmgrConfig = &TopologyAwarePolicy{}
```

**Functional options pattern** (`pkg/agent`):
```go
type Option func(*Agent) error

func WithKubeConfig(kc string) Option { ... }
func WithConfigNamespace(ns string) Option { ... }

agt, err := agent.New(cfgInterface, agent.WithKubeConfig(path))
```

**Named loggers per package:**
```go
var log = logger.NewLogger("my-component")
```

### Kubernetes Integration Patterns

- **controller-gen** generates deepcopy functions and CRD YAML from `+kubebuilder:` markers
- **code-generator** generates typed clientsets in `pkg/generated/`
- `make generate` runs both generators; generated files have `// Code generated by` headers and must not be hand-edited

---

## 10. Testing Architecture

### Unit Tests

- Standard `go test` with `testify/assert` and `testify/require`
- White-box tests (`package sysfs`) access unexported symbols directly
- `pkg/sysfs/utils_test.go` tests all generic parse/read helpers including named-type overflow cases

### Ginkgo/Gomega Integration Tests

Packages with a `*_suite_test.go` file use Ginkgo v2:
```go
// In pkg/sysfs/suite_test.go:
func TestSysfs(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "Sysfs Suite")
}
```

Individual specs use `Describe`/`Context`/`It`/`DescribeTable`/`Entry`.

Run: `make test` (Ginkgo runner) or `go test ./...` (all tests including non-Ginkgo).

### E2E Tests

Located in `test/e2e/`. Require a real Kubernetes cluster provisioned by Vagrant + QEMU:
- **Test suites:** `policies.test-suite/` (balloons, topology-aware) and `memory.test-suite/`
- **Topology variants:** directory names like `n4c16` = 4 NUMA nodes, 16 CPUs
- **Test DSL:** Bash scripts with `verify` expressions (Python-like assertions on CPU/memory assignments)
- **Run:** `make e2e-test` or `$(E2E_DIR)/run_tests.sh`

### Test Doubles

- Fake sysfs: `pkg/testutils/` provides a fake filesystem overlay for `pkg/sysfs`
- Fake K8s client: `pkg/generated/.../fake/` generated clientset for agent testing

---

## 11. Deployment Architecture

### Plugin Binaries

Each plugin compiles to a single static binary. Build:
```bash
make                      # build all plugins
make nri-resource-policy-balloons  # build one plugin
```

Binaries are placed in `build/bin/`.

### Container Images

One image per plugin, built via `make images` using `docker buildx`. Image tags follow `IMAGE_REPO/nri-resource-policy-<name>:IMAGE_VERSION`.

Multi-stage Dockerfiles: builder stage (Go compile) + minimal runtime image.

### Kubernetes Deployment

**Helm charts:** `deployment/helm/<plugin-name>/` — standard Kubernetes manifests with `DaemonSet`, `ServiceAccount`, `ClusterRole`, `ClusterRoleBinding`, CRD install, and a default `ConfigMap`/CRD instance.

**Operator:** `deployment/operator/` — Ansible-based Operator SDK operator for lifecycle management across all plugins.

**CRDs:** `config/crd/bases/` — generated from `+kubebuilder` markers via `make generate`.

### Runtime Requirements

- Kubernetes node with containerd ≥ 1.7 or CRI-O ≥ 1.26 (NRI v0.6+ enabled)
- `nri.conf` with `disable: false` in containerd config
- `hostPID: true` and `/sys` mounted for sysfs access
- Privileged or specific capabilities for cgroup writes

---

## 12. Extension and Evolution Patterns

### Adding a New Policy Plugin

1. **Create the command entry point:**
   ```
   cmd/plugins/<name>/main.go
   cmd/plugins/<name>/policy/<name>-policy.go
   ```

2. **Implement `policy.Backend`** in `<name>-policy.go`:
   ```go
   type myPolicy struct {
       options *policy.BackendOptions
       cfg     *cfgapi.Config
       cch     cache.Cache
   }
   func New() policy.Backend { return &myPolicy{} }
   // implement all Backend methods
   ```

3. **Create the CRD config type** in `pkg/apis/config/v1alpha1/`:
   - Add `Config` struct in `resmgr/policy/<name>/config.go`
   - Add CRD type in `pkg/apis/config/v1alpha1/types.go` with kubebuilder markers
   - Add `<name>-policy.go` with compile-time check and `ResmgrConfig` implementation
   - Add `ConfigInterface()` factory in `pkg/agent/`

4. **Register** in `Makefile` `PLUGINS` list.

5. **Generate** CRD manifests and deepcopy: `make generate`

6. **Add Helm chart** under `deployment/helm/<name>/`

### Modifying an Existing Policy

- Policy config changes → update `resmgr/policy/<name>/config.go` → run `make generate`
- Adding a new resource domain → add to `policy.Domain` constants and update `Backend.Setup()` + `Reconfigure()`
- Controller changes → work within `pkg/resmgr/control/`; do not import control packages from policy packages directly (use the cache as intermediary)

### Adding a New Hardware Resource

1. Add discovery in `pkg/sysfs/system.go` using the typed `readSysfsEntry[T]` helpers
2. Add the resource to `cache.Container` state
3. Expose via `policy.BackendOptions` if policies need it at setup time
4. Add a controller in `pkg/resmgr/control/` if kernel writes are needed

---

## 13. Architectural Decision Records

### ADR-001: Policy Backend as Interface, Not Registration

**Context:** Multiple resource policies needed to coexist in the same codebase but be deployed as separate binaries.  
**Decision:** Define `policy.Backend` as an interface; each plugin binary links exactly one concrete implementation. No plugin registry — the binary *is* the selection mechanism.  
**Consequence:** Clean separation; no accidental cross-policy dependencies. Adding a policy requires a new binary, not a new registration entry.

---

### ADR-002: CRD-Driven Live Configuration

**Context:** Static config files require pod restarts to update. Operators want to tune policy parameters without disrupting running workloads.  
**Decision:** Represent every plugin's configuration as a per-node Kubernetes CRD. The agent watches for changes and calls `Reconfigure()` on the policy without restarting.  
**Consequence:** Requires Kubernetes API access. File-based config retained as fallback for standalone/testing use.

---

### ADR-003: Typed Generics for sysfs I/O (replaces interface{}-based layer)

**Context:** The original `parseValue`/`parseValueList` functions parsed integers at 64-bit then silently cast to narrower types, causing integer truncation bugs (CodeQL findings in PR #676).  
**Decision:** Replace with generic `readSysfsEntry[T]` / `parseIntTo[T]` using `reflect.TypeOf(*new(T)).Size()*8` to correctly handle named types (e.g. `type ID int`).  
**Consequence:** All integer truncation risks eliminated at the type system level. Removed `unsafe.Sizeof`. Named types dispatch correctly without a type switch.

---

### ADR-004: Separate Go Module for `pkg/topology`

**Context:** The topology package is also useful outside the nri-plugins module (e.g., as a library dependency for schedulers).  
**Decision:** `pkg/topology` has its own `go.mod` and is imported via a `replace` directive in the root module.  
**Consequence:** Independent versioning; `make` handles it via `GO_SUBPKGS`. Tests must be run separately or via `make test`.

---

### ADR-005: No Panic in Production Paths

**Context:** NRI plugins run as DaemonSets; a panic crashes the entire plugin and leaves containers unmanaged.  
**Decision:** All production code paths return `error`; panics are reserved for programmer errors caught at startup. `log.Fatal` calls `os.Exit` via klog; it is not recoverable but is intentional.  
**Consequence:** Verbose error propagation but predictable failure modes.

---

## 14. Architecture Governance

### Automated Checks

| Check | Tool | Run |
|-------|------|-----|
| Lint (style, unused code, type safety) | `golangci-lint` v2.11.4 | `make golangci-lint` |
| Format | `gofmt` | `make fmt` |
| Vet | `go vet` | part of `make test` |
| CodeQL security scanning | GitHub Actions | `.github/workflows/` |
| Unit + integration tests | `go test` / Ginkgo | `make test` |
| CRD generation drift | `make generate` then `git diff` | CI |

### Structural Conventions

- Policy implementations live under `cmd/` not `pkg/` — preventing framework code from importing policies
- Generated files contain `// Code generated by` — never hand-edit them
- All `zz_generated.*.go` files are regenerated by `make generate`
- `pkg/topology` sub-module changes require updating both `pkg/topology/go.mod` and the root `go.mod` replace directive

### Commit Workflow

No direct commits by Copilot. Prepare commit message to file; user runs `git commit -F <file>`. No trailers (`Co-authored-by`, `Signed-off-by`) in commit messages per project policy.

---

## 15. Blueprint for New Development

### Starting Points by Feature Type

| Task | Starting Point |
|------|---------------|
| New resource policy | `cmd/plugins/template/` — copy and rename |
| New sysfs resource | `pkg/sysfs/system.go` + `pkg/sysfs/utils.go` |
| New config field | `pkg/apis/config/v1alpha1/resmgr/policy/<name>/config.go` → `make generate` |
| New metric | `pkg/instrumentation/metrics/` |
| New cache property | `pkg/resmgr/cache/cache.go` container interface |
| New Kubernetes integration | `pkg/agent/` (new watch type) |
| New hardware controller | `pkg/resmgr/control/<name>/` |

### Component Creation Sequence for a New Policy

```
1. pkg/apis/config/v1alpha1/resmgr/policy/<name>/config.go  (Config struct)
2. pkg/apis/config/v1alpha1/types.go                         (CRD type + kubebuilder markers)
3. pkg/apis/config/v1alpha1/<name>-policy.go                 (ResmgrConfig impl + var _ check)
4. pkg/agent/<name>.go                                       (ConfigInterface factory)
5. make generate                                             (deepcopy + CRD YAML)
6. cmd/plugins/<name>/policy/<name>-policy.go                (Backend impl)
7. cmd/plugins/<name>/main.go                                (3-line main)
8. Makefile PLUGINS list                                     (add binary name)
9. deployment/helm/<name>/                                   (Helm chart)
10. test/e2e/policies.test-suite/<name>/                     (E2E tests)
```

### Implementation Templates

**Minimal `policy.Backend` implementation:**
```go
package mypolicy

import (
    cfgapi "github.com/containers/nri-plugins/pkg/apis/config/v1alpha1/resmgr/policy/mypolicy"
    "github.com/containers/nri-plugins/pkg/resmgr/cache"
    "github.com/containers/nri-plugins/pkg/resmgr/events"
    policy "github.com/containers/nri-plugins/pkg/resmgr/policy"
    logger "github.com/containers/nri-plugins/pkg/log"
)

var log = logger.NewLogger("mypolicy")

const (
    PolicyName        = "mypolicy"
    PolicyDescription = "My new resource policy"
)

type myPolicy struct {
    options *policy.BackendOptions
    cfg     *cfgapi.Config
    cch     cache.Cache
}

func New() policy.Backend { return &myPolicy{} }

func (p *myPolicy) Name() string        { return PolicyName }
func (p *myPolicy) Description() string { return PolicyDescription }

func (p *myPolicy) Setup(opts *policy.BackendOptions) error {
    p.options = opts
    p.cch = opts.Cache
    cfg, ok := opts.Config.(*cfgapi.Config)
    if !ok {
        return fmt.Errorf("invalid config type %T", opts.Config)
    }
    p.cfg = cfg
    return nil
}

func (p *myPolicy) Reconfigure(cfg interface{}) error {
    newCfg, ok := cfg.(*cfgapi.Config)
    if !ok {
        return fmt.Errorf("invalid config type %T", cfg)
    }
    p.cfg = newCfg
    return nil
}

// AllocateResources, ReleaseResources, UpdateResources, Sync,
// Start, HandleEvent, ExportResourceData, GetTopologyZones...
```

### Common Pitfalls

| Pitfall | Correct Approach |
|---------|-----------------|
| Importing a concrete policy from `pkg/resmgr` | Always use `policy.Backend` interface only |
| Hand-editing `zz_generated.*.go` files | Run `make generate` after struct changes |
| Using `unsafe.Sizeof` for bit-width detection | Use `reflect.TypeOf(*new(T)).Size()*8` |
| Parsing sysfs integers with `strconv.ParseInt(..., 64)` then casting | Use `readSysfsEntry[T]` generic helper |
| Reading sysfs values with plain `string` returns | Use typed `readSysfsEntry[T]` or `readSysfsString` |
| Forgetting `var _ ResmgrConfig = &MyPolicy{}` | Add compile-time interface check to `<name>-policy.go` |
| Adding a new CRD field without running `make generate` | Always `make generate` + commit generated files |
| Panic on policy errors | Return `error`; only `log.Fatal` at unrecoverable startup failures |
| Creating loggers at function scope | Create package-level `var log = logger.NewLogger("name")` |

---

*This blueprint was generated from static analysis of the `containers/nri-plugins` repository as of 2026-06-15. Update it when: (a) new plugins are added, (b) the `policy.Backend` interface changes, (c) the CRD API version bumps, or (d) the sysfs/topology abstraction layer is restructured.*

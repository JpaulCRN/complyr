# Complyr — `go install` Launch Plan

**Audience:** internal software developers
**Distribution model:** `go install github.com/JpaulCRN/complyr@latest` as primary; pre-built binaries deferred to a later phase.
**Goal:** a teammate can run `go install ...@latest`, then `complyr scan` from any project directory and trust the output.

---

## 1. Status snapshot (verified by smoke test on this repo)

### Working today
- `complyr scan [path]` end-to-end on a Go project (default path = CWD)
- `complyr` with no args runs `scan` ([cmd/root.go:15](cmd/root.go#L15))
- TRL-based control assessment + progress bar to next TRL
- Banned-technology detection
- OSCAL JSON export (`--oscal file.json`) — produced 11 KB valid OSCAL on smoke test
- JSON output mode (`-j`) emits clean JSON to stdout
- OSCAL catalog cache lives in `os.UserCacheDir()/complyr/oscal-catalog.json` with 7-day TTL and stale-fallback on network failure
- Stderr/stdout separation: warnings go to stderr so `-j` output is pipeable
- `--verbose` flag inherited correctly from root by subcommands
- Build is clean (`go build ./...` passes)

### Working but unverified in this session
- `complyr init` interactive flow — compiles and starts, full survey not exercised
- npm / pnpm / yarn / Turborepo / Cargo / Go workspace detection
- CVE scanning against `api.github.com/advisories` (needs valid `GITHUB_TOKEN` to test at scale)
- Python / Java / Rust / JavaScript dependency parsing (only Go path was smoke-tested)

### Known gaps that block "I'd ship this"
- No `LICENSE` file (README claims MIT)
- No `--version` flag
- README has `yourusername` placeholders in install URLs
- `.complyr.yaml` tracked at repo root with personal config (`Phase I SBIR` / `Navy`)
- Zero tests anywhere in the codebase
- `go vet` warning at [cmd/init.go:39](cmd/init.go#L39) (`fmt.Println` redundant `\n`)
- `Complyr101.md` is an untracked draft that overlaps the README — pick one and delete the other

---

## 2. Phase 1 — Make `go install` actually work for a teammate

This is the smallest set of changes that produces a tool a coworker can try without immediately filing bugs.

### 1.1 Repo hygiene
- [ ] Push the repo to GitHub at `github.com/JpaulCRN/complyr` (must be **public** for `go install` to resolve)
- [ ] Add `LICENSE` file (MIT — matches README claim)
- [ ] Untrack `.complyr.yaml` (`git rm --cached .complyr.yaml`) and commit a `.complyr.example.yaml` instead. Add `.complyr.yaml` to `.gitignore` (the current gitignore has `!.complyr.yaml` which actively *un*-ignores it — flip that)
- [ ] Keep `Complyr101.md` — it's the canonical "why ATO matters" explainer for devs new to the framework. README stays the "how to install / use" reference. Don't merge them.
- [ ] Confirm `complyr`, `complyr.exe`, `complyr_test.exe` aren't tracked in git (gitignored already, but verify with `git ls-files | grep complyr`)

### 1.2 `--version` flag
- [ ] Add `--version` / `-V` to `rootCmd` using `runtime/debug.ReadBuildInfo()` so the version comes from the `go install` module info automatically. No `-ldflags` plumbing needed for the `go install` path.
  - When built via `go install github.com/JpaulCRN/complyr@v0.1.0`, `ReadBuildInfo().Main.Version` returns `v0.1.0`
  - When built locally (`go build`), it returns `(devel)` — fine, distinguishes dev builds from released ones

### 1.3 README install section
- [ ] Replace the entire "Installation" block with:
  ```
  ## Install

  Requires Go 1.21+.

      go install github.com/JpaulCRN/complyr@latest

  This drops the `complyr` binary into `$GOBIN` (default `~/go/bin`).
  Make sure that directory is on your PATH:

      # macOS / Linux (bash/zsh)
      export PATH="$PATH:$(go env GOPATH)/bin"

      # Windows (PowerShell, persistent)
      [Environment]::SetEnvironmentVariable("Path",
        "$env:Path;$(go env GOPATH)\bin", "User")

  Verify:

      complyr --version
  ```
- [ ] Remove the `curl ... releases/latest/download/...` snippets (we don't have releases yet — they 404)
- [ ] Replace all `yourusername/complyr` with `JpaulCRN/complyr` (search the file)

### 1.4 Pre-tag sanity
- [ ] Fix the `go vet` warning at [cmd/init.go:39](cmd/init.go#L39)
- [ ] Run `go mod tidy` to make sure dependencies are minimal
- [ ] Run `go build ./...` clean
- [ ] Run `go vet ./...` clean

### 1.5 Tag the first version
- [ ] `git tag v0.1.0 && git push origin v0.1.0`
- [ ] Verify from a fresh shell (or a coworker's machine):
  ```
  go install github.com/JpaulCRN/complyr@v0.1.0
  complyr --version    # should print v0.1.0
  cd ~/some-project
  complyr scan
  ```

**Phase 1 done = a coworker can `go install` and run a scan without your help.**

---

## 3. Phase 2 — Confidence that it isn't broken

These don't block the tag but they should land before the tool gets recommended widely.

### 2.1 Minimal test suite
- [ ] `internal/scanners/vulnerabilities_test.go` — table-driven tests for `parseSemver`, `compareSemver`, `isVersionInRange`. These are the highest-impact correctness bugs (they decide whether something gets flagged as a CVE) and they're pure functions.
- [ ] `internal/core/oscal_catalog_test.go` — test `MapTRLToImpactLevel`, `GetSoftwareBaseline`. Trivial but pins the TRL→baseline contract.
- [ ] `internal/scanners/dependencies_test.go` — fixture-based tests: a `testdata/` folder with sample `package.json`, `go.mod`, `requirements.txt`, run the parser, assert N deps with expected names.
- [ ] One end-to-end test: `cmd/scan_test.go` that runs `PerformScan` against `testdata/sample-go-project/` and asserts the result has the expected shape.

### 2.2 Verify each language path manually
Build a `testdata/` folder with one minimal project per supported language and confirm `complyr scan` produces a non-empty dependency list:
- [ ] Node.js (`package.json` with one dep)
- [ ] Python (`requirements.txt` with one dep)
- [ ] Java (`pom.xml` with one dep)
- [ ] Rust (`Cargo.toml` with one dep)
- [ ] Go (already verified)

### 2.3 Verify each workspace type
- [ ] Turborepo (`turbo.json` + 2 packages)
- [ ] npm workspaces (`package.json` with `workspaces` array)
- [ ] pnpm (`pnpm-workspace.yaml`)
- [ ] Go workspace (`go.work`)
- [ ] Cargo workspace (`Cargo.toml` with `[workspace]`)

### 2.4 Verify CVE path with a known-vulnerable dep
- [ ] Build a fixture with `lodash@4.17.19` (known CVE) and confirm a finding appears
- [ ] Build a fixture with a git-pinned dep (e.g. `"foo": "github:user/repo#abc123"`) and confirm it lands in the "skipped — unparseable version" warning, not as a false-positive CVE

**Phase 2 done = `go test ./...` passes in CI and every advertised feature has been exercised at least once.**

---

## 4. Phase 3 — UX polish for first-time users

### 3.1 First-run experience
- [ ] Detect missing `GITHUB_TOKEN` and warn once at start of CVE scan: *"No GITHUB_TOKEN set — CVE lookups limited to ~60 requests/hour. Export `GITHUB_TOKEN` for higher limits."*
- [ ] If `complyr` is run with no args and no `.complyr.yaml`, after the TRL-3-default warning, suggest `complyr init` *before* scanning (currently the warning fires but scan continues — fine, but make the init suggestion more prominent)

### 3.2 New flags
- [ ] `--no-color` / `--plain` — suppress ANSI codes and emoji for log-friendly output. Auto-enable when `os.Stdout` isn't a TTY ([mattn/go-isatty](https://github.com/mattn/go-isatty) is already an indirect dep).
- [ ] Document exit codes (`0`/`1`/`2`) in `complyr scan --help` long description, not just README.

### 3.3 Catalog management
- [ ] `complyr update-catalog` subcommand — force-refresh the OSCAL cache, print where it lives. Useful when NIST publishes a new revision.

### 3.4 README clarity for non-DoD readers
- [ ] Add a one-paragraph "**What's TRL and do I need to care?**" before the TRL table. For internal devs not on a federal contract, frame it as "pick the maturity level closest to your project; higher = more controls checked."

**Phase 3 done = the tool feels finished, not just functional.**

---

## 5. Phase 4 — Defer until there's demand

Don't build any of this until someone asks.

- GitHub Actions CI (`.github/workflows/ci.yml` — `go test`, `go vet`, `golangci-lint` on PR)
- GoReleaser config + release workflow (pre-built binaries for win/mac/linux on `v*` tag)
- Homebrew tap, Scoop bucket
- Docker image (rejected for filesystem-scanner UX reasons; could revisit for CI use)
- Issue/PR templates, `CONTRIBUTING.md`, `SECURITY.md`
- Dependabot config
- SBOM for the tool itself

---

## 6. Phase 1 ship checklist (the actual punch list)

Copy this into a GitHub issue when you're ready to start:

```
- [ ] git rm --cached .complyr.yaml; commit .complyr.example.yaml
- [ ] Flip .gitignore: remove `!.complyr.yaml` line
- [ ] Add LICENSE (MIT)
- [ ] Add --version via runtime/debug.ReadBuildInfo + cobra rootCmd.Version
- [ ] Rewrite README "Installation" → "Install" using `go install`
- [ ] Replace yourusername → JpaulCRN throughout README
- [ ] Fix cmd/init.go:39 fmt.Println redundant \n
- [ ] go mod tidy && go build ./... && go vet ./...
- [ ] Push to github.com/JpaulCRN/complyr (public)
- [ ] git tag v0.1.0 && git push origin v0.1.0
- [ ] Cold-shell verification: `go install ...@v0.1.0; complyr --version`
```

**Estimate: ~2 hours of focused work for a clean Phase 1 ship.**

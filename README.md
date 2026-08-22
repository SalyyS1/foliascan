# FoliaScan

Tell whether a Minecraft plugin jar will actually survive on [Folia](https://github.com/PaperMC/Folia)
— by reading its bytecode, not its README.

```
$ foliascan MyPlugin.jar

MyPlugin 1.4.2  (MyPlugin.jar)
  folia-supported   not declared
  classes scanned   214
  Folia API usage   0 call site(s) (no migration work detected)

   BLOCKER   FS001  Plugin does not declare folia-supported: true
      plugin.yml   plugin.yml has no `folia-supported: true`

  CRITICAL FS030  Scoreboard registration is not implemented on Folia  (2 sites)
      com.example.hud.HudService#build (HudService.java:61)   Scoreboard.registerNewObjective()
      com.example.hud.HudService#team (HudService.java:74)    Scoreboard.registerNewTeam()

   WARNING FS063  Entity API touched from an off-region context
      com.example.stats.Collector#flush (Collector.java:88)   Player.getHealth()
        reached off-region: handed to ExecutorService.submit (entry point Collector.schedule, 2 call(s) deep)

Summary: 1 blocker, 2 critical, 1 warning, 0 info
Verdict: Will not load on Folia.
```

Works on any jar — including one you did not compile. Server owners can check a paid plugin
before installing it; developers can gate a release in CI.

## Why this exists

Folia's threading changes are not gradual. Some very ordinary Bukkit calls stop working
completely, and nothing tells you until a player triggers the code path:

- **The entire legacy scheduler is dead.** Folia inserts an unconditional
  `if (true) throw new UnsupportedOperationException()` into `CraftScheduler#handle`, so every
  `runTask`, `runTaskLater`, `runTaskTimer` and async variant throws. Not "on the wrong
  thread" — always.
- **The Scoreboard API is not implemented.** `registerNewObjective`, `registerNewTeam`,
  `clearSlot`, `getNewScoreboard` and `Player#setScoreboard` all throw unconditionally. Every
  scoreboard HUD, stat sidebar and team system breaks.
- **Runtime world creation is gone.** `createWorld` and `unloadWorld` throw.
- **Synchronous teleports are rejected** with `Must use teleportAsync while in region threading`.
- **`Entity`, `World`, `Block` and `BlockState` calls are region-guarded.** Folia wraps
  `CraftEntity#getHandle` — and ~170 subclass overrides — in a thread check, so touching an
  entity from a thread that does not own it throws.

Adding `folia-supported: true` silences the loader, not the exceptions. FoliaScan finds the
call sites that will still blow up.

## Install

Requires Java 21+.

Download `foliascan-<version>.jar` from
[Releases](https://github.com/SalyyS1/foliascan/releases) and run it:

```bash
java -jar foliascan-0.1.2.jar MyPlugin.jar
```

Or build from source:

```bash
./gradlew build          # runs the test suite too
java -jar build/libs/foliascan-0.1.2.jar MyPlugin.jar
```

## Usage

```
foliascan [OPTIONS] TARGET...

  TARGET                          plugin jar(s), or a directory of jars

  --format console|json|sarif     output format (default: console)
  -o, --output PATH               write the report to a file
  --fail-on LEVEL                 blocker|critical|warning|info|never (default: critical)
  --all                           report relocated dependency packages too
  --include PACKAGE               only scan this package (repeatable)
  --exclude PACKAGE               skip this package (repeatable)
  --disable RULE_ID               turn a rule off (repeatable)
  --baseline FILE                 suppress findings listed in FILE
  --write-baseline FILE           record current findings as accepted, then exit 0
  --no-color                      plain output
  -v, --verbose                   list every call site instead of the first 8
  --rules                         print the rule catalog with sources, then exit
```

Exit codes: `0` clean at the chosen threshold, `1` findings at or above it, `2` bad usage.

Scan a whole server directory:

```bash
foliascan /srv/mc/plugins --fail-on blocker
```

### In CI

```yaml
- name: Check Folia compatibility
  run: |
    java -jar foliascan.jar build/libs/*.jar \
      --format sarif -o foliascan.sarif --fail-on critical

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: foliascan.sarif
```

Adopting on a large legacy plugin? Record what exists today and fail only on new problems:

```bash
foliascan MyPlugin.jar --write-baseline foliascan-baseline.json   # once
foliascan MyPlugin.jar --baseline foliascan-baseline.json         # every build
```

Fingerprints deliberately exclude line numbers, so editing code above a call site does not
resurrect a suppressed finding.

## Rules

Run `foliascan --rules` for the full text of each one, including the Folia source it came from.

| Id | Severity | What it catches |
|----|----------|-----------------|
| FS001 | blocker | descriptor missing `folia-supported: true` — Folia refuses to load the plugin |
| FS002 | warning | the `folia-supported` flag was written by a patcher, not by the author |
| FS010 | critical | `Bukkit.getScheduler()` / `Server#getScheduler()` |
| FS011 | critical | any call on `BukkitScheduler`, including via a stored field |
| FS012 | critical | class extends `BukkitRunnable` |
| FS020 | critical | synchronous `Entity#teleport` |
| FS030 | critical | `Scoreboard#registerNewObjective` / `registerNewTeam` / `clearSlot` |
| FS031 | critical | `ScoreboardManager#getNewScoreboard`, `Player#setScoreboard` |
| FS040 | critical | `createWorld`, `unloadWorld` |
| FS041 | critical | `World#getTickableTileEntityCount` |
| FS050 | warning | `getTPS`, `getAverageTickTime` read off-region |
| FS051 | warning | `dispatchCommand` off-region |
| FS060 | warning | region-guarded `World` calls (`getChunkAt`, `loadChunk`, `setBiome`, …) |
| FS061 | warning | region-guarded `Block` calls (`getBlockState`, `breakNaturally`, …) |
| FS062 | warning | region-guarded `BlockState` calls (`getDrops`, `randomTick`) |
| FS063 | warning | any `org.bukkit.entity` call from an off-region context |
| FS070 | warning | direct `net.minecraft` / `org.bukkit.craftbukkit` access |
| FS080 | info | `isPrimaryThread()` used as a safety gate |

Severities mean specific things:

- **blocker** — the plugin will not load at all.
- **critical** — Folia throws whenever the code runs, on any thread. Reported unconditionally.
- **warning** — legal from the region that owns the data, fatal from anywhere else. Only
  reported when the call sits in a context FoliaScan can show is off-region.
- **info** — behaviour differs enough to need a human decision.

## How it works

1. Parse every class with ASM. Nothing is loaded or executed, and no bytecode is written.
2. Read `paper-plugin.yml` / `plugin.yml` for the descriptor, then work out the plugin's own
   package. `main` alone is not enough — plugins commonly park the entry class in a platform
   subpackage (`dev.aurelium.auraskills.bukkit.AuraSkills`) while most of the code lives in
   sibling packages, so the root is widened to the longest package prefix every class in the jar
   shares, as far as that prefix still lies on `main`'s path. The report prints the root it chose
   and how many of the jar's classes it covers.
3. Find off-region entry points: a lambda or `Runnable` handed to an executor, a
   `CompletableFuture` async stage, a raw `Thread`, `runTask*Asynchronously`, or Paper's
   `AsyncScheduler`.
4. Propagate that breadth-first across in-jar call edges, so a helper called from an async
   task is reported too — with the entry point and depth printed next to the finding.
5. Apply the rule table, keeping one finding per source line.

Relocated dependencies are analysed but not blamed. A compatibility shim like FoliaLib
deliberately contains a legacy `BukkitScheduler` implementation for non-Folia servers, so
reporting it is noise; the code still counts toward "Folia API usage" and still taints the plugin
code it calls. Two signals identify it: build-tool folder names (`libs`, `shaded`, `vendor`, …)
and a curated list of library leaf names, because relocation often leaves no marker folder at all
(`dev.aurelium.auraskills.kyori`). That list is necessarily incomplete, so every subtree it
matches is named in the report notes, `--exclude` adds your own, and `--all` turns it off.

## Related tools

FoliaScan reports; it does not modify your jar.

**[FoliaPhantom / pasta](https://github.com/MARVserver/pasta)** (MIT) rewrites plugin bytecode to
route legacy scheduler calls through its own shim. Different job, and useful if you want a server
to boot today. Two things to know if you use it: `PluginPatcher#modifyPluginDescriptor` appends
`folia-supported: true` unconditionally, without analysing whether the result is region-safe, and
its own README disclaims thread-safety guarantees. So a patched jar's declared flag is a machine's
assumption, not the author's claim — which is what rule **FS002** exists to surface. FoliaScan
detects the runtime classes pasta bundles and says so instead of trusting the flag.

**[folia-checker](https://github.com/IronDiscipline-Project/folia-checker)** (MIT) is a VS Code
extension applying line-by-line regular expressions to `.java` sources. Source-only, Java-only,
and regex granularity means it cannot separate `runTaskAsynchronously` from `runTask` without
hand-tuned patterns.

**[FoliaLib](https://github.com/technicallycoded/FoliaLib)** and similar are runtime helper
libraries: they help you *write* Folia-compatible code. FoliaScan tells you whether you already
did. They compose — a jar bundling FoliaLib scans clean, because relocated shim code is analysed
but not blamed.

## What it does not do

Worth reading before treating a clean run as a guarantee.

- **A clean result is not a proof of correctness.** It means none of the enabled rules matched.
- **Calls leaving the jar are not followed.** If an async entry point lives in a dependency and
  calls back into your code by interface, the taint can be missed.
- **Reflection, injected executors and thread pools obtained from other plugins are invisible.**
- **A helper used from both sync and async callers is reported.** That is intentional — it
  genuinely may run off-region — but it is not always a bug.
- **`--fail-on critical` only judges unconditional failures.** Region-guarded misuse that
  FoliaScan cannot place in an off-region context will not appear at all.
- Findings need line numbers to be actionable; a jar stripped of debug info still gets class and
  method attribution, but no lines.

## Where the rules come from

Every rule cites a file and member inside Folia's own patch set, printed with each finding and
listed by `foliascan --rules`. The dataset behind the table was extracted mechanically, not
recalled: `tools/extract_folia_throws.py` walks a Folia checkout and reports every added
`throw new UnsupportedOperationException`, every `TickThread.ensureTickThread` guard, and the
`@Deprecated` marker on `BukkitScheduler`.

```bash
git clone --depth 1 https://github.com/PaperMC/Folia.git /tmp/folia
python tools/extract_folia_throws.py /tmp/folia
```

Re-run it when Folia changes to check the table is still accurate. Rules were verified against
Folia at the 1.21.11 branch state on 2026-08-22.

No Folia or Paper source is vendored, copied or redistributed here. The rule table references
class and member names and quotes short diagnostic strings so that each claim can be audited.

FoliaScan is an independent tool and is not affiliated with or endorsed by PaperMC.

## Contributing

New rules need a provenance entry pointing at the Folia source that justifies them, plus a
fixture in `src/test/kotlin/fixtures/` proving both that the rule fires on bad code and that it
stays quiet on the region-aware equivalent. Rules without evidence will not be merged — the
value of this tool is that its output can be checked.

```bash
./gradlew test
```

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for third-party attributions.

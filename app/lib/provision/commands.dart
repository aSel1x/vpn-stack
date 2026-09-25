// Every shell program this layer sends, in one place, so the tests can script a
// fake against the exact strings and so a reader can see what runs on the box
// without reading Dart control flow.
//
// Raw strings throughout: `$$`, `$4` and `\.` must reach the remote shell
// unmangled, and Dart interpolation would eat all three. Parameters are
// substituted through @PLACEHOLDER@ markers instead.
//
// POSIX sh, not bash: the command goes to whatever login shell sshd hands us,
// which on Debian may be dash. No `[[`, no arrays, no `local`.
//
// Two rules about those markers, both paid for:
//
//   1. A placeholder is filled with a [ShellArg], never a String. `@HOST@`
//      comes from a free-text field that is validated for non-emptiness and
//      nothing else, and it used to land in `bash "@SCRIPT@" "@HOST@"` by raw
//      replaceAll: a double quote broke out of the argument, and `$(...)`,
//      backticks and `$VAR` all expand inside double quotes. The quiet version
//      of that bug is the one that would actually have bitten -- a `$` in the
//      host is substituted away, `VPN_SERVER_HOST` in /etc/vpn-stack/.env is
//      silently wrong, and every VLESS and Hysteria2 URI the server issues
//      afterwards carries the wrong address with nothing to show for it.
//   2. A placeholder stands alone as a whole shell word. Never inside quotes,
//      never glued to a quoted string, because a quoted word does not nest:
//      splicing `'a'\''b'` inside `"..."` ends the double-quoted string, and
//      splicing it inside `sh -c '...'` ends that one. Where a value is used
//      more than once, or has to appear in a message, it is assigned to a shell
//      variable on its own line and the body uses `"$var"`.

import '../control/shell.dart';
import '../control/vpnctl.dart' show lockConflictExit;
import 'config.dart';

/// A value that is safe to splice into shell program text, because the only way
/// to make one is through the quoter in `control/shell.dart`.
///
/// The type is the mechanism: [_fill] takes these and not Strings, so there is
/// no expression anywhere in this layer that puts an unquoted value into a
/// program. `shellQuote` was already here, tested, and called from nowhere that
/// sent anything.
class ShellArg {
  /// One shell word.
  ShellArg(String value) : text = shellQuote(value);

  /// Several words, each quoted, joined by the spaces that separate them.
  ///
  /// For the one template that genuinely wants word splitting -- `for spec in
  /// @SPECS@`. Quoting the joined string instead would hand the loop a single
  /// item named "10443/tcp 20443/udp".
  ShellArg.words(List<String> values) : text = shellCommand(values);

  /// The quoted form, and the only thing that reaches a program.
  final String text;
}

/// Shell program text, and the only thing `ProvisionContext.run` accepts.
///
/// The constructor is private to this file, so a step cannot hand `run` a
/// string it built with Dart interpolation: a program can only come from a
/// template below, and every value a template takes is a [ShellArg].
class RemoteProgram {
  const RemoteProgram._(this.text);

  final String text;

  @override
  String toString() => text;
}

final RegExp _unfilled = RegExp(r'@[A-Z0-9_]+@');

RemoteProgram _fill(String program, Map<String, ShellArg> values) {
  String out = program;
  values.forEach((String key, ShellArg value) {
    out = out.replaceAll(key, value.text);
  });
  if (_unfilled.hasMatch(out)) {
    // A mistyped marker otherwise reaches the box as a literal path and comes
    // back as "no such file or directory" three steps from the mistake.
    throw StateError(
      'unfilled placeholder ${_unfilled.firstMatch(out)!.group(0)} in:\n$out',
    );
  }
  return RemoteProgram._(out);
}

/// Distribution check. Parsed rather than grepped: ID_LIKE decides for a
/// derivative, and the docker repository path differs between debian and ubuntu.
const RemoteProgram osReleaseCommand = RemoteProgram._('cat /etc/os-release');

/// `vpnctl` needs root, and so does every step here. Failing on the first
/// `install -d /etc/vpn-stack` instead says "permission denied" and nothing else.
const RemoteProgram whoamiCommand = RemoteProgram._('id -u');

const String _provisionedProbe = r'''
set -u
vpnctl=@VPNCTL@
state=@STATE@
[ -x "$vpnctl" ] && echo vpnctl=yes || echo vpnctl=no
[ -d "$state" ] && echo state_dir=yes || echo state_dir=no
[ -f "$state/users.json" ] && echo users_file=yes || echo users_file=no
secrets=$(ls -1 "$state/secrets" 2>/dev/null | wc -l | tr -d ' ')
echo "secrets=$secrets"
''';

RemoteProgram provisionedProbeCommand(ProvisionConfig config) =>
    _fill(_provisionedProbe, <String, ShellArg>{
      '@VPNCTL@': ShellArg(config.vpnctl),
      '@STATE@': ShellArg(config.stateDir),
    });

/// Exit status is the answer; there is no output to parse.
const RemoteProgram dockerPresentCommand =
    RemoteProgram._('command -v docker >/dev/null 2>&1');

const RemoteProgram dockerVersionCommand = RemoteProgram._('docker --version');

/// The compose plugin is a separate package, and a docker without it fails
/// three layers down inside composectl.
const RemoteProgram dockerComposeCommand =
    RemoteProgram._('docker compose version');

// The one shell in this file that restates the server-local half rather than
// calling it. It stays for one reason, and it is not inertia: this picks the
// apt repository from ID/ID_LIKE, while provision-host.sh's install_docker()
// hardcodes `linux/ubuntu`. preflight accepts Debian, so on a Debian box with
// no docker this step is what keeps the install correct -- fold the two
// together when that copy learns about debian, and not before.
//
// Ordering note: this runs before the clone, so it cannot call a script that is
// not on the box yet.
//
// The family probe is not belt and braces: CloudFront fronts that repository
// and answers 403 over IPv4 to some ranges while serving the same bytes over
// IPv6 -- observed on this stack's own host. ForceIPv6 is persisted because
// otherwise the operator's own next `apt update` fails on the docker repo, and
// reverted if the system mirror turns out to have no IPv6, rather than leaving
// apt broken.
const String _installDocker = r'''
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || true
apt-get install -y -qq ca-certificates curl
. /etc/os-release
case "${ID:-}" in
  ubuntu) repo=ubuntu ;;
  debian) repo=debian ;;
  *) case " ${ID_LIKE:-} " in
       *ubuntu*) repo=ubuntu ;;
       *debian*) repo=debian ;;
       *) echo "not a Debian or Ubuntu system (ID=${ID:-?}); install docker yourself and re-run" >&2; exit 1 ;;
     esac ;;
esac
[ -n "${VERSION_CODENAME:-}" ] || { echo "/etc/os-release has no VERSION_CODENAME; install docker yourself and re-run" >&2; exit 1; }
key="https://download.docker.com/linux/$repo/gpg"
family=
for f in 4 6; do
  if curl -"$f" -fsS -m 15 -o /dev/null "$key" 2>/dev/null; then family=$f; break; fi
done
[ -n "$family" ] || { echo "download.docker.com is unreachable over IPv4 and IPv6. Install docker yourself and re-run: a docker that is already there is left completely alone." >&2; exit 1; }
[ "$family" = 6 ] && echo "IPv4 to download.docker.com refused; using IPv6" || true
install -m 0755 -d /etc/apt/keyrings
curl -"$family" -fsSL "$key" -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
  "$(dpkg --print-architecture)" "$repo" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
if [ "$family" = 6 ]; then echo 'Acquire::ForceIPv6 "true";' > /etc/apt/apt.conf.d/99-vpn-stack-ipv6; fi
apt-get update -qq || {
  rm -f /etc/apt/apt.conf.d/99-vpn-stack-ipv6 /etc/apt/sources.list.d/docker.list
  apt-get update -qq || true
  echo "apt could not read the docker repository; reverted, nothing left behind." >&2
  exit 1
}
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker --version
''';

const RemoteProgram _installDockerProgram = RemoteProgram._(_installDocker);

RemoteProgram installDockerCommand() => _installDockerProgram;

// git is the clone's own prerequisite, so it is installed here rather than in a
// step of its own.
//
// `checkout --force --detach FETCH_HEAD` rather than `reset --hard`, and rather
// than the `-B "$ref"` it used to be. A shallow fetch leaves the ref it fetched
// behind and a stale ref is how a deploy lands an older tree than the one asked
// for -- but the ref here is a TAG, and checking a tag out as a branch of the
// same name leaves refs/heads/v0.2.0 beside refs/tags/v0.2.0, which makes every
// later `git rev-parse v0.2.0` on that box ambiguous. Detaching leaves no branch
// to go stale and no name to collide, and it is the state a fresh
// `clone --depth 1 --branch <tag>` produces anyway, so both halves of this `if`
// end the same way.
//
// The existence check at the end is not belt and braces. `main` had no
// scripts/provision-host.sh -- the script is a pure addition -- so a provision
// against a branch cloned perfectly and then died on the host stage at exit 127,
// with apt and git already touched and nothing naming the ref or the file. A
// tree that cannot serve this build of the app is a fact the clone knows, so the
// clone is where it is said.
const String _cloneRepo = r'''
set -eu
export DEBIAN_FRONTEND=noninteractive
repo=@PATH@
url=@URL@
ref=@REF@
script=@SCRIPT@
command -v git >/dev/null 2>&1 || { apt-get update -qq || true; apt-get install -y -qq git; }
if [ -d "$repo/.git" ]; then
  git -C "$repo" remote set-url origin "$url"
  git -C "$repo" fetch --depth 1 origin "$ref"
  git -C "$repo" checkout -q --force --detach FETCH_HEAD
elif [ -d "$repo" ] && [ -n "$(ls -A "$repo" 2>/dev/null)" ]; then
  echo "$repo exists and is not a git checkout (an rsynced tree from the CLI path?); move it aside and re-run" >&2
  exit 1
else
  mkdir -p "$repo"
  git clone -q --depth 1 --branch "$ref" "$url" "$repo"
fi
[ -f "$repo/$script" ] || { echo "this build of the app needs a server tree containing $script; ref $ref has none" >&2; exit 1; }
head=$(git -C "$repo" rev-parse --short HEAD)
echo "head=$head"
''';

RemoteProgram cloneRepoCommand(ProvisionConfig config) =>
    _fill(_cloneRepo, <String, ShellArg>{
      '@PATH@': ShellArg(config.repoPath),
      '@URL@': ShellArg(config.repoUrl),
      '@REF@': ShellArg(config.repoRef),
      '@SCRIPT@': ShellArg(config.hostScript),
    });

// The server-local half, run from the checkout, one stage per call.
//
// `scripts/provision-host.sh` takes a stage and one argument -- `base <host>`
// or `code <repo-path>` -- and the split is the whole reason this layer exists:
// `base` installs ufw and everything else a box can do to itself, the firewall
// step then proves a fresh connection survives, and only then does `code`
// install vpnctl and mint the keyring. A bootstrap on a box we have locked
// ourselves out of is a server to rebuild, not one to reconnect to.
//
// The existence test is in the same program so a checkout without that script
// fails here, naming it, instead of failing two steps later on a missing
// vpnctl.
//
// For `base` the argument is the value that ends up in VPN_SERVER_HOST, which
// every share link is built from. It is quoted on the way in and passed as one
// word: a host silently truncated at a `$` produces profiles that point
// somewhere else and a server that looks perfectly healthy.
const String _hostStage = r'''
set -eu
export PATH="/usr/local/bin:/root/.local/bin:$PATH"
script=@SCRIPT@
stage=@STAGE@
arg=@ARG@
[ -f "$script" ] || { echo "$script is not in this checkout: the server-local half of install.sh has to exist as a script for the app to call it" >&2; exit 127; }
bash "$script" "$stage" "$arg"
''';

/// apt packages, docker, uv, `/etc/vpn-stack` and VPN_SERVER_HOST, the sysctls,
/// `/dev/ppp` and the boot unit. Needs no vpnctl and installs ufw, so the
/// firewall step runs after it.
RemoteProgram hostBaseCommand(ProvisionConfig config) =>
    _fill(_hostStage, <String, ShellArg>{
      '@SCRIPT@': ShellArg(config.hostScriptPath),
      '@STAGE@': ShellArg('base'),
      '@ARG@': ShellArg(config.host),
    });

/// The `.env` symlink, `uv sync`, the `/usr/local/bin/vpnctl` shim and
/// `vpnctl bootstrap`, from the checkout. Runs after the firewall is proved,
/// because this is the step that mints credentials.
RemoteProgram hostCodeCommand(ProvisionConfig config) =>
    _fill(_hostStage, <String, ShellArg>{
      '@SCRIPT@': ShellArg(config.hostScriptPath),
      '@STAGE@': ShellArg('code'),
      '@ARG@': ShellArg(config.repoPath),
    });

// Every vpnctl invocation this layer sends goes through the lock, exactly as
// `./vpn`'s remote(), install.sh, deploy.sh, provision-host.sh's own bootstrap
// and the boot unit do. vpnctl takes /run/vpn-stack.lock itself now, for every
// mutating command, and this outer flock is still the load-bearing half rather
// than a leftover: it covers the WHOLE remote command -- the shell around the
// call, and anything this layer sends after it -- while vpnctl's own window
// opens after argparse and closes when the process exits. app/README.md is flat
// about it: a call that skips the lock is a bug even on the run where it works.
// The race is not hypothetical -- two processes rendering candidate trees over
// each other is the one thing the atomic promote downstream cannot save you
// from, because both halves are valid and merely come from different inputs.
//
// `-w` and `-E 75` where the shell call sites use a bare `flock`: a phone
// blocking for ever with nothing on screen is indistinguishable from a crash,
// and 75 (EX_TEMPFAIL) is the one status reserved for "somebody else is
// mid-apply" on both sides of the handshake -- vpnctl's own refusal exits 75
// too, and its other statuses are 1 for a refusal, 2 for argparse or the
// not-the-server guard and 127 for a missing shim -- so busy stays
// distinguishable from broken whichever half decided it.
// ProvisionContext.runVpnctl translates it.
//
// VPN_STACK_LOCK_HELD is the handshake that keeps the two halves from fighting
// over one file, and it is why this is `flock` around vpnctl rather than one or
// the other: flock(1) inside flock(1) on the same path from a child process
// opens a second file description, which the kernel treats as a different
// holder, so the inner wait never returns (measured on this stack) and an outer
// `-w` does not bound it. The variable tells vpnctl the caller already holds
// the file, so it skips taking it; vpnctl's own non-blocking acquire is the
// second line of defence, refusing with 75 rather than hanging if a call site
// ever forgets to set it.
//
// `env` rather than a bare `VAR=1 cmd` prefix: the same list is then valid as an
// argv and as a shell word, so nothing here depends on which of the two a
// caller happens to want.
List<String> _lockedVpnctl(ProvisionConfig config, List<String> command) =>
    <String>[
      'env',
      'VPN_STACK_LOCK_HELD=1',
      'flock',
      '-w',
      '${config.lockWait.inSeconds}',
      '-E',
      '$lockConflictExit',
      config.lockPath,
      config.vpnctl,
      ...command,
    ];

/// The shim from a bare environment, which is where one that forgot its own
/// PATH fails -- and, incidentally, the first call that would notice a box with
/// no `flock`, by name, instead of letting `apply` be the one that dies on it.
RemoteProgram vpnctlReadyCommand(ProvisionConfig config) => _fill(
      r'@ARGV@ >/dev/null',
      <String, ShellArg>{
        '@ARGV@': ShellArg.words(_lockedVpnctl(config, <String>['--help'])),
      },
    );

/// Render, validate, promote, converge.
///
/// The payload is not read here. This layer verifies by observing what is bound
/// afterwards, which is the stronger check: `apply` only *warns* when a port
/// never came up and still returns ok, so believing its receipt is how a server
/// that is not serving passes a readiness step.
RemoteProgram applyCommand(ProvisionConfig config) => _fill(
      r'@ARGV@',
      <String, ShellArg>{
        '@ARGV@':
            ShellArg.words(_lockedVpnctl(config, <String>['apply', '--json'])),
      },
    );

// There is deliberately no `protocol list` program here. That answer is parsed,
// and the strict parser already exists one layer over: readiness asks through
// `Vpnctl.listProtocols()`, which refuses a row it cannot read BY NAME. The
// loose copy that used to live here skipped any row it could not understand, so
// "nothing parsed" became "nothing is enabled" and the readiness wait reported
// success without waiting for anything.

const String _smoke = r'''
set -eu
cd @PATH@
bash scripts/smoke.sh --json
''';

RemoteProgram smokeCommand(ProvisionConfig config) =>
    _fill(_smoke, <String, ShellArg>{'@PATH@': ShellArg(config.repoPath)});

// ufw is checked before the deadman is armed: a deadman whose body is
// `ufw --force disable` is not a safety net on a box with no ufw.
//
// A live predecessor is refused, never written over, and this is the sharp edge
// of the whole step. The failing proof leaves its deadman armed ON PURPOSE and
// tells the operator to wait and try again; somebody who reconnects in thirty
// seconds and taps retry arrives here with an earlier timer still sleeping and
// its pid still in the file. Run A armed pid 100, run B's subshell writes 200
// over the same path -- and whichever of the two the disarm reads, the other
// wakes at its own T+180 and runs `ufw --force disable`, possibly minutes after
// this reported success. An unattended firewall-off is meant to be the ONE
// thing this net causes. Measured with a stubbed ufw under dash: without this
// block the earlier timer is still sleeping after a successful disarm. Clearing
// the file when nothing is alive closes a second race in the same place -- the
// wait loop below only tests that the file is non-empty, so a stale pid
// satisfies it and `armed=` reports the old timer instead of the new one.
//
// Refused rather than killed, which is where this and provision-host.sh's
// deadman_arm deliberately differ. A pid in a file the previous run did not
// clean up may have been recycled by the kernel, and signalling a process group
// we did not create -- on a box whose firewall is about to change -- is a worse
// accident than stopping. There is also nothing to recover: the timer switches
// ufw off by itself, which is the entire contract, so waiting is the fix and the
// message says so.
//
// The subshell records its OWN pid. `$!` is unreliable because setsid forks
// when the caller is already a process-group leader, and setsid also makes the
// child a group leader -- which is what lets the disarm kill the group and take
// the sleep with it instead of leaving a timer that fires on a healthy server.
//
// The pid file and the timeout go into that subshell as positional parameters,
// not spliced into its body: the body is a single-quoted string, and a quoted
// word inside a quoted word does not nest -- it ends it. `sh -c BODY NAME ARGS`
// sets $0 to NAME, which is why "deadman" is there.
const String _armDeadman = r'''
set -eu
pidfile=@PID@
ttl=@TTL@
command -v ufw >/dev/null 2>&1 || { echo "ufw is not installed; the host step was supposed to install it" >&2; exit 1; }
if [ -s "$pidfile" ]; then
  old=$(tr -dc '0-9' < "$pidfile")
  if [ -n "$old" ] && { kill -0 -"$old" 2>/dev/null || kill -0 "$old" 2>/dev/null; }; then
    echo "a deadman from an earlier run is still armed (process group $old). It disables ufw by itself when its timer expires, and arming a second one on top of it leaves whichever this run does not record to fire later on a healthy server. Wait for it to expire and try again, or stop that process group from a console." >&2
    exit 1
  fi
  rm -f "$pidfile"
fi
setsid sh -c 'echo $$ > "$1"
              sleep "$2"
              ufw --force disable
              rm -f "$1"' deadman "$pidfile" "$ttl" </dev/null >/dev/null 2>&1 &
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$pidfile" ] && break; sleep 0.2; done
[ -s "$pidfile" ] || { echo "deadman failed to arm; refusing to touch ufw" >&2; exit 1; }
pid=$(cat "$pidfile")
echo "armed=$pid"
''';

RemoteProgram armDeadmanCommand(ProvisionConfig config) =>
    _fill(_armDeadman, <String, ShellArg>{
      '@PID@': ShellArg(config.deadmanPidFile),
      '@TTL@': ShellArg('${config.deadmanSeconds}'),
    });

// Existing rules are kept, not reset, and only a rule carrying a vpn-stack:
// comment is added -- the same contract firewall.reconcile honours on the
// server.
const String _enableUfw = r'''
set -eu
port=@PORT@
ufw allow "$port"/tcp comment 'vpn-stack:ssh' >/dev/null
if ufw status 2>/dev/null | grep -q '^Status: active'; then
  echo "ufw was already active; allowed $port/tcp and left the existing rules alone"
else
  ufw --force enable >/dev/null
  echo "ufw was inactive; enabled it (existing rules kept, not reset)"
fi
ufw status | head -1
''';

RemoteProgram enableUfwCommand(ProvisionConfig config) =>
    _fill(_enableUfw, <String, ShellArg>{
      '@PORT@': ShellArg('${config.sshPort}'),
    });

// Disarming is the one step here that is allowed to fail, and it has to be able
// to. This program was `kill -TERM` with both kills' stderr discarded, an
// unconditional `rm -f` of the pid file BEFORE anything checked, and a closing
// `true`: it could not exit non-zero whatever happened, so a kill that did not
// land left a timer counting down towards `ufw --force disable` on a healthy
// server with the one record of its existence deleted. provision-host.sh's
// deadman_kill was hardened into TERM, poll until it is provably gone, KILL,
// poll again -- and these two are halves of one safety net, so they have to
// agree about what disarming means.
//
// Negative pid first, so the `sleep` dies with its leader; the plain pid is the
// fallback for a group the kernel has already torn down. Under root a signal to
// one of our own processes cannot be refused, so the escalation is defence in
// depth; what the polling really buys is that a surviving timer is REPORTED,
// with its pid, instead of being assumed dead.
//
// The pid file is removed only once the process is provably gone, and left in
// place otherwise: it is the single record of a live timer, and deleting it
// while the timer breathes is the one irreversible mistake available here.
//
// A missing pid file is fatal rather than a shrug: either the timer already
// fired, in which case ufw is off right now and the operator has to know, or it
// was never armed, in which case the firewall went up with nothing under it.
const String _disarmDeadman = r'''
set -u
pidfile=@PID@
alive() { kill -0 -"$1" 2>/dev/null || kill -0 "$1" 2>/dev/null; }
[ -s "$pidfile" ] || {
  echo "no deadman pid file at $pidfile. Either its timer already expired -- in which case ufw is off right now, check \`ufw status\` -- or nothing ever armed it and the firewall went up with no net under it. Neither is a state to call an install finished from." >&2
  exit 1; }
pid=$(tr -dc '0-9' < "$pidfile" 2>/dev/null || true)
[ -n "$pid" ] || {
  echo "$pidfile holds no pid this can read, so there is no way to tell what to kill. A deadman may still be counting down towards \`ufw --force disable\`." >&2
  exit 1; }
kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
i=0
while [ "$i" -lt 25 ]; do alive "$pid" || break; sleep 0.2; i=$((i + 1)); done
if alive "$pid"; then
  kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
  i=0
  while [ "$i" -lt 10 ]; do alive "$pid" || break; sleep 0.2; i=$((i + 1)); done
fi
if alive "$pid"; then
  echo "deadman pid $pid survived TERM and KILL. It runs \`ufw --force disable\` when its timer expires, on a server that is fine. Kill it by hand from a console: kill -KILL -$pid. $pidfile is left in place -- it is the only record that it is still counting." >&2
  exit 1
fi
rm -f "$pidfile"
echo "disarmed=$pid"
''';

RemoteProgram disarmDeadmanCommand(ProvisionConfig config) =>
    _fill(_disarmDeadman, <String, ShellArg>{
      '@PID@': ShellArg(config.deadmanPidFile),
    });

/// What the prover runs. Connecting proves the handshake passed the new rules;
/// running something proves the session is usable.
///
/// An argv element, not a program: it goes to `session.run(['true'])`, which
/// control's transport quotes itself.
const String proveCommand = 'true';

// "Bound" means bound on a non-loopback address, exactly as smoke.sh and
// composectl define it. Substring-matching the port number reports dnstt's
// 53/udp as served on any stock Ubuntu, because systemd-resolved holds
// 127.0.0.53:53 -- a check that passes on a server where nothing of ours serves
// DNS at all.
//
// @SPECS@ is the one placeholder that is several words: each spec is quoted on
// its own and the shell splits between them, which is what `for` is reading.
const String _portsBound = r'''
served() {
  if [ "$2" = tcp ]; then flag=-ltn; else flag=-lun; fi
  ss -H $flag "sport = :$1" 2>/dev/null | awk '
    { a = $4; sub(/:[0-9]+$/, "", a); sub(/%.*/, "", a)
      if (a !~ /^127\./ && a != "[::1]" && a != "::1") found = 1 }
    END { exit !found }'
}
for spec in @SPECS@; do
  port=${spec%/*}; proto=${spec#*/}
  if served "$port" "$proto"; then echo "bound=$spec"; else echo "pending=$spec"; fi
done
''';

RemoteProgram portsBoundCommand(List<String> specs) =>
    _fill(_portsBound, <String, ShellArg>{'@SPECS@': ShellArg.words(specs)});

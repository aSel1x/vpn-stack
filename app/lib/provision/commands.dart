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
// step of its own. `checkout --force -B` rather than `reset --hard`: a shallow
// fetch leaves the branch ref behind, and a stale ref is how a deploy lands an
// older tree than the one asked for.
const String _cloneRepo = r'''
set -eu
export DEBIAN_FRONTEND=noninteractive
repo=@PATH@
url=@URL@
ref=@REF@
command -v git >/dev/null 2>&1 || { apt-get update -qq || true; apt-get install -y -qq git; }
if [ -d "$repo/.git" ]; then
  git -C "$repo" remote set-url origin "$url"
  git -C "$repo" fetch --depth 1 origin "$ref"
  git -C "$repo" checkout -q --force -B "$ref" FETCH_HEAD
elif [ -d "$repo" ] && [ -n "$(ls -A "$repo" 2>/dev/null)" ]; then
  echo "$repo exists and is not a git checkout (an rsynced tree from the CLI path?); move it aside and re-run" >&2
  exit 1
else
  mkdir -p "$repo"
  git clone -q --depth 1 --branch "$ref" "$url" "$repo"
fi
head=$(git -C "$repo" rev-parse --short HEAD)
echo "head=$head"
''';

RemoteProgram cloneRepoCommand(ProvisionConfig config) =>
    _fill(_cloneRepo, <String, ShellArg>{
      '@PATH@': ShellArg(config.repoPath),
      '@URL@': ShellArg(config.repoUrl),
      '@REF@': ShellArg(config.repoRef),
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

RemoteProgram vpnctlReadyCommand(ProvisionConfig config) => _fill(
      r'@ARGV@ >/dev/null',
      <String, ShellArg>{
        '@ARGV@': ShellArg.words(<String>[config.vpnctl, '--help']),
      },
    );

RemoteProgram applyCommand(ProvisionConfig config) => _fill(
      r'@ARGV@',
      <String, ShellArg>{
        '@ARGV@': ShellArg.words(<String>[config.vpnctl, 'apply', '--json']),
      },
    );

RemoteProgram protocolListCommand(ProvisionConfig config) => _fill(
      r'@ARGV@',
      <String, ShellArg>{
        '@ARGV@':
            ShellArg.words(<String>[config.vpnctl, '--json', 'protocol', 'list']),
      },
    );

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

/// Negative pid first, so the `sleep` dies with its leader; the plain pid is the
/// fallback for a kernel that already reaped the group.
const String _disarmDeadman = r'''
pidfile=@PID@
pid=$(cat "$pidfile" 2>/dev/null || true)
[ -n "$pid" ] && { kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null; }
rm -f "$pidfile"
true
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

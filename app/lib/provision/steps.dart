// The sequence, in order. install.sh's five SSH sessions, plus the two things a
// script on the box cannot do: refuse a server that already has credentials,
// and prove a fresh connection survives the firewall.
//
// The split this follows is app/README.md's: everything that can run on the
// server runs there, in one place, as `scripts/provision-host.sh`. That script
// is two stages and this list interleaves them -- `base` (docker, apt packages,
// uv, the state directory, sysctls, /dev/ppp, the boot unit), then the firewall
// proof, then `code` (uv sync, the vpnctl shim, the keyring). The app
// orchestrates and owns the proof; neither side reimplements the other, because
// two definitions of how a host is prepared drift and the drift only shows up
// on a box nobody has yet.

import 'commands.dart';
import 'errors.dart';
import 'firewall.dart';
import 'readiness.dart';
import 'ssh.dart';
import 'step.dart';

/// The steps, in the order they run.
List<ProvisionStep> provisionSteps() => <ProvisionStep>[
      const ProvisionStep(
        name: 'preflight',
        label: 'Checking the server',
        run: preflight,
      ),
      const ProvisionStep(
        name: 'docker',
        label: 'Installing Docker',
        run: installDocker,
      ),
      const ProvisionStep(
        name: 'clone',
        label: 'Fetching vpn-stack',
        run: cloneRepo,
      ),
      const ProvisionStep(
        name: 'host',
        label: 'Preparing the host',
        run: prepareHost,
      ),
      const ProvisionStep(
        name: 'firewall',
        label: 'Closing the firewall (with a way back in)',
        run: runFirewallStep,
      ),
      const ProvisionStep(
        name: 'bootstrap',
        label: 'Installing vpnctl and generating the keyring',
        run: bootstrapKeyring,
      ),
      const ProvisionStep(
        name: 'apply',
        label: 'Rendering config and starting the containers',
        run: applyConfig,
      ),
      const ProvisionStep(
        name: 'readiness',
        label: 'Waiting for the ports to bind',
        run: awaitReadiness,
      ),
      const ProvisionStep(
        name: 'verify',
        label: 'Checking it is really serving',
        run: verify,
      ),
    ];

/// Reachable, root, Debian-ish, and NOT already carrying credentials.
Future<void> preflight(ProvisionContext ctx) async {
  await ctx.openPrimary();
  ctx.progress('connected (${ctx.primaryTransportId})');

  // Root first. Everything after this writes to /etc, and without it the
  // failure arrives four steps later as a permission denied with no context.
  final CommandResult who = await ctx.runChecked(
    whoamiCommand,
    what: 'asking who we are',
  );
  if (who.stdout.trim() != '0') {
    throw UnsupportedHostError(
      step: ctx.stepName,
      message: 'this connects as uid ${who.stdout.trim()}, not root. vpnctl '
          'drives docker, iptables and ufw and writes /etc/vpn-stack, so it '
          'needs root. Connect as root, or as a user whose shell is root.',
    );
  }

  final CommandResult os = await ctx.runChecked(
    osReleaseCommand,
    what: 'reading /etc/os-release',
  );
  final Map<String, String> release = parseOsRelease(os.stdout);
  final String id = release['ID'] ?? '';
  final String like = release['ID_LIKE'] ?? '';
  final bool debianish = id == 'debian' ||
      id == 'ubuntu' ||
      like.split(' ').contains('debian') ||
      like.split(' ').contains('ubuntu');
  if (!debianish) {
    final String named = release['PRETTY_NAME'] ??
        (id.isEmpty ? 'a system with no readable /etc/os-release' : id);
    throw UnsupportedHostError(
      step: ctx.stepName,
      message: 'this is $named. Provisioning installs docker from an apt '
          'repository and drives ufw, so it needs Debian or Ubuntu. Everything '
          'after the install works anywhere docker does -- install docker and '
          'ufw yourself and this will leave both alone.',
    );
  }
  ctx.facts['os'] = release['PRETTY_NAME'] ?? id;
  ctx.progress(ctx.facts['os'] ?? id);

  final CommandResult probe = await ctx.runChecked(
    provisionedProbeCommand(ctx.config),
    what: 'looking for an existing install',
  );
  final int secrets = int.tryParse(valueOf(probe.stdout, 'secrets') ?? '') ?? 0;
  final bool users = valueOf(probe.stdout, 'users_file') == 'yes';
  final List<String> evidence = <String>[
    if (users) '${ctx.config.stateDir}/users.json exists',
    if (secrets > 0) '$secrets secrets in ${ctx.config.stateDir}/secrets',
  ];
  if (evidence.isNotEmpty) {
    // deploy.sh refuses to bootstrap for this exact reason, and this is the
    // same refusal one layer up: fresh secrets on a server that already has
    // users invalidate every profile already handed out, and nothing says so.
    throw AlreadyProvisionedError(step: ctx.stepName, evidence: evidence);
  }
  if (valueOf(probe.stdout, 'vpnctl') == 'yes' ||
      valueOf(probe.stdout, 'state_dir') == 'yes') {
    // A half-finished install, with nothing to destroy. Continue: an install
    // that fails halfway has to be fixable by running it again, not by hand.
    ctx.progress('a previous attempt left files here but no keyring; continuing');
  }
}

/// Docker, only if it is not already there.
Future<void> installDocker(ProvisionContext ctx) async {
  final CommandResult present = await ctx.run(dockerPresentCommand);
  if (present.ok) {
    final CommandResult version = await ctx.run(dockerVersionCommand);
    final String text = version.stdout.trim();
    ctx.facts['docker'] = text;
    // Everything already installed is left alone, and says so: bringing your
    // own docker is a supported way to run this, and silence looks like the
    // script deciding to reinstall it.
    ctx.progress('${text.isEmpty ? 'docker' : text} -- left alone');
  } else {
    ctx.progress('installing docker from download.docker.com (apt, signed)');
    final CommandResult installed = await ctx.runChecked(
      installDockerCommand(),
      what: 'installing docker',
    );
    ctx.facts['docker'] = installed.stdout.trim().split('\n').last.trim();
  }
  // A docker without the compose plugin fails several layers down inside
  // composectl, where the message is about a missing subcommand.
  await ctx.runChecked(
    dockerComposeCommand,
    what: 'checking for the docker compose plugin',
  );
}

/// The repository, cloned by the server itself.
///
/// It is public now, so there is no credential to hold and the app ships no
/// copy of the tree -- which is what removed install.sh's reason to rsync a
/// working checkout from a laptop that a phone does not have.
Future<void> cloneRepo(ProvisionContext ctx) async {
  ctx.progress('git clone ${ctx.config.repoUrl} (${ctx.config.repoRef})');
  // The ref is in the `what`, because the failure this step now catches is
  // about the ref and not about the clone: a tree with no
  // scripts/provision-host.sh cannot serve this build of the app, and saying so
  // here beats exit 127 on the host stage with apt and git already touched.
  final CommandResult result = await ctx.runChecked(
    cloneRepoCommand(ctx.config),
    what: 'cloning ${ctx.config.repoUrl} at ${ctx.config.repoRef}',
  );
  final String head = valueOf(result.stdout, 'head') ?? '';
  if (head.isNotEmpty) {
    ctx.facts['head'] = head;
    ctx.progress('at $head');
  }
}

/// `provision-host.sh base`: everything the box can do to itself.
///
/// Not the whole server-local half -- that script is two stages, and the split
/// is this layer's reason to exist. `base` installs ufw among other things and
/// needs no vpnctl, so the firewall proof goes between the two stages.
Future<void> prepareHost(ProvisionContext ctx) async {
  ctx.progress('docker, apt packages, uv, /etc/vpn-stack, sysctls, /dev/ppp, '
      'boot unit');
  await ctx.runChecked(
    hostBaseCommand(ctx.config),
    what: 'running ${ctx.config.hostScriptPath} base',
  );
}

/// `provision-host.sh code`: vpnctl, and the keyring.
///
/// After the firewall has been proved, on purpose. This stage ends in
/// `vpnctl bootstrap`, and a keyring minted on a box we have locked ourselves
/// out of is a server to rebuild rather than one to reconnect to.
Future<void> bootstrapKeyring(ProvisionContext ctx) async {
  // Not wrapped in a lock from here: the stage takes it itself, around its own
  // `vpnctl bootstrap`. flock(1) inside flock(1) on the same path from a child
  // process opens a second file description and blocks for ever, so the outer
  // one would hang this step on a healthy box.
  await ctx.runChecked(
    hostCodeCommand(ctx.config),
    what: 'running ${ctx.config.hostScriptPath} code',
  );
  // The stage runs `vpnctl --help` itself, with uv's directory exported. This
  // runs the shim from a bare environment instead -- which is what systemd does
  // at boot, and where a shim that forgot its own PATH fails.
  await ctx.runVpnctl(
    vpnctlReadyCommand(ctx.config),
    what: 'checking vpnctl runs',
  );
  ctx.facts['bootstrap'] = 'generated';
  // Said plainly because it is the irreversible one: from here the server holds
  // keys that profiles are issued against, and a second bootstrap invalidates
  // every profile already handed out. That is what preflight refuses over.
  ctx.progress('vpnctl installed, keyring generated');
}

/// Render, validate, converge.
Future<void> applyConfig(ProvisionContext ctx) async {
  await ctx.runVpnctl(
    applyCommand(ctx.config),
    what: 'rendering and converging',
  );
  // Not "it is serving": apply only *warns* when a port never bound and still
  // returns ok. The readiness step decides that, from what is bound.
  ctx.progress('containers converged');
}

/// Wait for the ports the enabled protocols claim.
Future<void> awaitReadiness(ProvisionContext ctx) async {
  final List<String> specs = await enabledPortSpecs(ctx);
  ctx.facts['expected_ports'] = specs.join(' ');
  await waitForPorts(ctx, specs);
}

/// The same assertions the CLI path runs: is it actually serving?
Future<void> verify(ProvisionContext ctx) async {
  final CommandResult result = await ctx.run(smokeCommand(ctx.config));
  if (result.ok) {
    ctx.progress('every check passed');
    return;
  }
  throw ProvisionCommandError(
    step: ctx.stepName,
    what: 'the smoke test',
    exitCode: result.exitCode,
    output: result.combined,
  );
}

/// `/etc/os-release` as a map, quotes stripped.
///
/// Parsed rather than grepped because ID_LIKE is what decides for a derivative,
/// and "does the word ubuntu appear anywhere in this file" is true of things
/// that are not Ubuntu.
Map<String, String> parseOsRelease(String text) {
  final Map<String, String> out = <String, String>{};
  for (final String raw in text.split('\n')) {
    final String line = raw.trim();
    if (line.isEmpty || line.startsWith('#')) continue;
    final int eq = line.indexOf('=');
    if (eq <= 0) continue;
    final String key = line.substring(0, eq).trim();
    String value = line.substring(eq + 1).trim();
    if (value.length >= 2 &&
        ((value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'")))) {
      value = value.substring(1, value.length - 1);
    }
    out[key] = value;
  }
  return out;
}

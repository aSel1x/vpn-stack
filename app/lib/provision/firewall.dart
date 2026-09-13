// The step that cannot move to the server, and the reason this layer exists
// instead of one `ssh box bash install.sh`.
//
// A detached deadman disables ufw unconditionally after a timeout. It is armed
// BEFORE the first `ufw enable`, and disarmed only after a brand-new SSH
// connection -- new TCP handshake, evaluated by the rules just installed --
// succeeds. A script on the box cannot do the disarming half: from inside one
// established connection it cannot prove that a DIFFERENT connection would
// survive rules it is about to install. The prover has to be somewhere else,
// and here that is the phone.
//
// Two properties of the arming are load-bearing and live in commands.dart, not
// here: the subshell records its OWN pid (`$!` is unreliable because setsid
// forks when the caller is already a process-group leader) and the disarm kills
// the process GROUP (so the `sleep` dies with it, rather than leaving a timer
// that disables the firewall on a healthy server twenty minutes later).
//
// The third property is this file's, and it is about the prover: the connection
// must be genuinely new. A second channel multiplexed onto the connection we
// already hold proves nothing -- an established conntrack entry survives a
// firewall that would reject every new connection. `SshConnector.connect()`
// promises a new transport (the interface-level `-o ControlMaster=no
// -o ControlPath=none`), and because a promise in a doc comment is not a check,
// the prover also compares transport ids and refuses to accept its own.
//
// The fourth is the disarm, and it is the one this file got wrong. The disarm
// runs on the connection that was just PROVED, never on the primary session.
// install.sh does the same thing for the same reason -- its disarm goes through
// `on`, which is a fresh `ssh` invocation, not the session that enabled ufw.
// The state this step exists to survive is "new connections are fine, the
// established one is not": `ufw enable` can drop the session that issued it
// while every new connection sails through. Disarming over the primary throws
// in exactly that case, the run aborts, and the firewall then disables itself
// 180 seconds later on a server that was never broken.

import 'dart:async';

import 'commands.dart';
import 'errors.dart';
import 'ssh.dart';
import 'step.dart';

/// Arms the deadman, enables ufw, proves a fresh connection survives, disarms.
///
/// Every failure path between the arming and the proof leaves the deadman
/// ARMED. That is deliberate and is the whole safety net: the server undoes the
/// firewall by itself, with nothing further from this app and nothing for the
/// operator to run -- which is the only recovery available to somebody whose
/// only way in is the connection that just stopped working.
Future<void> runFirewallStep(ProvisionContext ctx) async {
  final CommandResult armed = await ctx.runChecked(
    armDeadmanCommand(ctx.config),
    what: 'arming the deadman',
  );
  final String pid = valueOf(armed.stdout, 'armed') ?? 'unknown';
  ctx.facts['deadman_pid'] = pid;
  ctx.progress(
    'deadman armed (pid $pid): the server disables ufw by itself in '
    '${ctx.config.deadmanSeconds}s unless we disarm it',
  );

  // From here to the disarm, nothing may exit this function normally. Note the
  // enable is inside the net too: a connection that dies during `ufw enable` is
  // not a transport hiccup, it is the lockout, and it has to be reported with
  // the sentence that says the box will recover on its own.
  try {
    final CommandResult enabled = await ctx.runChecked(
      enableUfwCommand(ctx.config),
      what: 'enabling ufw',
    );
    for (final String line in enabled.combined.split('\n')) {
      if (line.trim().isNotEmpty) ctx.progress(line.trim());
    }
  } on ProvisionException catch (error) {
    throw FirewallLockoutError(
      step: ctx.stepName,
      reason: 'ufw could not be enabled: ${error.message}',
      deadmanSeconds: ctx.config.deadmanSeconds,
      deadmanPid: pid,
    );
  }

  final List<String> attempts = <String>[];
  for (int attempt = 1; attempt <= ctx.config.proveAttempts; attempt++) {
    if (attempt > 1) await ctx.clock.sleep(ctx.config.proveGap);
    ctx.progress(
      'opening a brand-new connection through the new rules '
      '(attempt $attempt of ${ctx.config.proveAttempts})',
    );
    final _Proof proof = await _prove(ctx);
    final SshConnection? proven = proof.connection;
    if (proven != null) {
      ctx.progress('fresh connection accepted -- disarming the deadman on it');
      try {
        // On the proven connection, not on ctx.session. The primary may be the
        // one casualty of the rules we just installed, and it is the one
        // connection whose survival this step has NOT established.
        await _disarm(ctx, proven, pid);
      } finally {
        await _closeProver(ctx, proven);
      }
      return;
    }
    attempts.add('  attempt $attempt: ${proof.failure}');
  }

  // More than one attempt because the cost is asymmetric: a false failure costs
  // a re-run and a three-minute wait, a false success disarms the safety net on
  // a server nobody can reach any more.
  throw FirewallLockoutError(
    step: ctx.stepName,
    reason: 'Tried ${ctx.config.proveAttempts} times; none got through.',
    deadmanSeconds: ctx.config.deadmanSeconds,
    deadmanPid: pid,
    attempts: attempts,
  );
}

/// One attempt: either an open connection that proved itself, or the sentence
/// saying why there is not one.
class _Proof {
  _Proof.proved(SshConnection this.connection) : failure = null;

  _Proof.failed(String this.failure) : connection = null;

  /// Left OPEN on success, and owned by the caller: the disarm runs on it.
  final SshConnection? connection;

  final String? failure;
}

/// Opens one genuinely new connection and runs one command on it.
///
/// It does not throw: a failure here is an expected outcome of the step, not an
/// accident, and the caller decides what it means. On success the connection
/// stays open, because the next thing that has to happen -- the disarm -- is
/// the one command in this step that must not go over the primary session.
Future<_Proof> _prove(ProvisionContext ctx) async {
  SshConnection? fresh;
  try {
    fresh = await openVerified(
      ctx.connector,
      ctx.hostKeys,
      timeout: ctx.config.proveTimeout,
    );
    final String? own = ctx.primaryTransportId;
    if (own != null && fresh.transportId == own) {
      // Not a network failure -- a broken connector. Reported as a failure to
      // prove, because it is: whatever this connection tells us, it cannot tell
      // us that a NEW one would have been let through.
      final String why = 'the connector handed back the connection already open '
          '(transport ${fresh.transportId}). A multiplexed channel rides an '
          'established conntrack entry, which survives a firewall that rejects '
          'every new connection, so it proves nothing.';
      await _closeProver(ctx, fresh);
      return _Proof.failed(why);
    }
    final SshHostKey? expected = ctx.primaryHostKey;
    if (expected != null && !fresh.hostKey.sameKeyAs(expected)) {
      // A fresh connection to a DIFFERENT machine proves nothing about this
      // one, and is worth saying out loud rather than counting as success: at
      // this moment the address either moved or somebody moved it.
      final String why = 'the fresh connection presented a different host key '
          '(${fresh.hostKey.fingerprint}) than the session that installed the '
          'rules (${expected.fingerprint}). Whatever answered, it is not the '
          'machine this step just firewalled.';
      await _closeProver(ctx, fresh);
      return _Proof.failed(why);
    }
    final CommandResult result = await fresh.session
        .run(<String>[proveCommand]).timeout(ctx.config.proveTimeout);
    if (!result.ok) {
      final String why = 'connected, but `$proveCommand` exited '
          '${result.exitCode}: ${result.combined}';
      await _closeProver(ctx, fresh);
      return _Proof.failed(why);
    }
    return _Proof.proved(fresh);
  } on TimeoutException {
    // A firewall that DROPs does not refuse, it hangs. Without this the step
    // waits forever while the deadman quietly runs down behind it.
    if (fresh != null) await _closeProver(ctx, fresh);
    return _Proof.failed(
      'no answer within ${ctx.config.proveTimeout.inSeconds}s (a DROP does not '
      'refuse, it hangs)',
    );
  } on Object catch (error) {
    if (fresh != null) await _closeProver(ctx, fresh);
    return _Proof.failed('$error');
  }
}

/// Kills the deadman, over the connection that was just proved, and treats
/// failing to as fatal.
///
/// Leaving it armed on a server that is demonstrably fine means ufw disables
/// itself minutes later with nobody watching -- a firewall that silently
/// switches off is worse than an install that stops and says so. Re-running is
/// safe: nothing has been bootstrapped yet, so preflight will not refuse.
Future<void> _disarm(
  ProvisionContext ctx,
  SshConnection proven,
  String pid,
) async {
  final String what = 'disarming the deadman (pid $pid) -- ufw will disable '
      'itself in ${ctx.config.deadmanSeconds}s on a server that is fine; wait '
      'for that and run this again';
  final CommandResult result = await _runOn(
    ctx,
    proven,
    disarmDeadmanCommand(ctx.config),
    what,
  );
  if (result.ok) return;
  throw ProvisionCommandError(
    step: ctx.stepName,
    what: what,
    exitCode: result.exitCode,
    output: result.combined,
  );
}

/// Runs one program on a connection this step owns, rather than on ctx.session.
///
/// The transport throwing here is not the lockout -- that connection answered
/// `true` seconds ago -- but it is still a deadman left running, so it is
/// reported with the same sentence.
Future<CommandResult> _runOn(
  ProvisionContext ctx,
  SshConnection connection,
  RemoteProgram program,
  String what,
) async {
  try {
    return await connection.session
        .run(<String>['sh', '-c', program.text]).timeout(ctx.config.proveTimeout);
  } on Object catch (error) {
    throw ProvisionTransportError(step: ctx.stepName, cause: error, what: what);
  }
}

Future<void> _closeProver(ProvisionContext ctx, SshConnection prover) async {
  try {
    await prover.close();
  } on Object catch (error) {
    ctx.progress('note: could not close the prover connection: $error');
  }
}

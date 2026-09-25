// One step of the sequence, and the context every step runs in.
//
// Steps are a list rather than a function with nine sections because this takes
// minutes on a real box -- apt fetching docker, the first ipsec run building an
// NSS database -- and a phone showing nothing is indistinguishable from a hang.
// A named, ordered, individually-reporting step is what lets the screen say
// which of the nine it is on and what that one is doing.

import '../control/control.dart';
import 'commands.dart';
import 'config.dart';
import 'errors.dart';
import 'ssh.dart';

/// Where a step is in its life. `progress` fires any number of times between
/// `started` and the one terminal event.
enum StepPhase { started, progress, succeeded, failed }

/// Something worth putting on the screen.
class ProvisionEvent {
  const ProvisionEvent({
    required this.step,
    required this.label,
    required this.phase,
    required this.message,
    required this.index,
    required this.total,
  });

  /// The step's stable machine name. Safe to switch on and safe to persist;
  /// [label] is not, and is free to be reworded.
  final String step;
  final String label;
  final StepPhase phase;
  final String message;

  /// 1-based, so "3 of 9" needs no arithmetic at the call site.
  final int index;
  final int total;

  @override
  String toString() => '[$index/$total] $step ${phase.name}: $message';
}

typedef ProvisionReporter = void Function(ProvisionEvent event);

/// Time, injected.
///
/// The readiness wait is minutes of polling and the prover retries with a gap
/// between attempts. Both are real waits on a real box and neither may be a
/// real wait in a test, or the suite that guards the lockout path becomes the
/// suite nobody runs.
class ProvisionClock {
  const ProvisionClock();

  DateTime now() => DateTime.now();

  Future<void> sleep(Duration duration) => Future<void>.delayed(duration);
}

/// Everything a step is given: the config, the live connection, a way to open
/// another one, a clock, and somewhere to report.
class ProvisionContext {
  ProvisionContext({
    required this.config,
    required this.connector,
    required this.hostKeys,
    this.clock = const ProvisionClock(),
    this._onEvent,
  });

  final ProvisionConfig config;
  final SshConnector connector;

  /// Who decides the server's host key, and who gets asked about one nobody has
  /// seen before. Required, with no permissive default: dartssh2 accepts any
  /// host key unless it is told not to, and this is the only thing in the layer
  /// positioned to tell it.
  final HostKeyPolicy hostKeys;

  final ProvisionClock clock;
  final ProvisionReporter? _onEvent;

  /// What the steps learned, in the order they learned it: the distribution,
  /// the cloned commit, the deadman's pid, which protocols came up. The UI
  /// shows it and a bug report quotes it.
  final Map<String, String> facts = <String, String>{};

  ProvisionStep? _step;
  int _index = 0;
  int _total = 0;
  SshConnection? _primary;

  /// The runner's, not a step's. Named rather than private because the runner
  /// lives in another file and Dart has no package-private.
  void beginStep(ProvisionStep step, int index, int total) {
    _step = step;
    _index = index;
    _total = total;
  }

  String get stepName => _step?.name ?? 'provision';

  void emit(StepPhase phase, String message) {
    final ProvisionReporter? sink = _onEvent;
    if (sink == null) return;
    sink(
      ProvisionEvent(
        step: stepName,
        label: _step?.label ?? '',
        phase: phase,
        message: message,
        index: _index,
        total: _total,
      ),
    );
  }

  /// A line for the screen from inside a step that is still running.
  void progress(String message) => emit(StepPhase.progress, message);

  /// The connection every step but the prover runs on.
  ///
  /// Opened by preflight, because reachability *is* preflight: a server that
  /// cannot be reached should fail on the first row of the list, named, rather
  /// than before the list exists.
  Future<void> openPrimary() async {
    if (_primary != null) return;
    try {
      _primary = await openVerified(connector, hostKeys);
    } on HostKeyError {
      // Not dressed up as a transport failure. "The connection failed" sends
      // somebody to look at their network; this is a question about who
      // answered, and it already carries its own paragraph.
      rethrow;
    } on Object catch (error) {
      throw ProvisionTransportError(
        step: stepName,
        cause: error,
        what: 'opening the first connection',
      );
    }
    facts['transport'] = _primary!.transportId;
    facts['host_key'] = _primary!.hostKey.fingerprint;
  }

  SshSession get session {
    final SshConnection? open = _primary;
    if (open == null) {
      throw StateError('no connection yet: preflight opens the primary one');
    }
    return open.session;
  }

  /// The control layer, over this connection.
  ///
  /// There is one reader of `--json` in this app and it is this one: it takes
  /// the lock, and it refuses a payload it does not fully understand by name.
  /// Provisioning used to keep a loose copy for the one answer it needed and
  /// skipped every row that copy could not read, so an answer it could not
  /// understand at all became an empty list and the readiness wait reported
  /// success without waiting for anything.
  Vpnctl get vpnctl => Vpnctl(
        session,
        vpnctlPath: config.vpnctl,
        lockPath: config.lockPath,
        lockWait: config.lockWait,
      );

  /// One control call, with every way it can fail mapped into this layer's
  /// family so a failure always names the step it happened in.
  ///
  /// The three outcomes stay apart because they ask different things: a
  /// transport failure is worth retrying, a lock conflict means nothing ran,
  /// and an answer this app cannot read is neither -- it is a version
  /// disagreement, and the control layer has already said which field.
  Future<T> control<T>(
    Future<T> Function(Vpnctl vpnctl) call, {
    required String what,
  }) async {
    try {
      return await call(vpnctl);
    } on VpnctlTransportError catch (error) {
      throw ProvisionTransportError(
        step: stepName,
        cause: error.cause,
        what: what,
      );
    } on VpnctlCommandError catch (error) {
      if (error.exitCode == lockConflictExit) {
        throw _lockBusy(what);
      }
      throw ProvisionControlError(step: stepName, what: what, cause: error);
    } on VpnctlException catch (error) {
      throw ProvisionControlError(step: stepName, what: what, cause: error);
    }
  }

  /// The one status the lock owns -- whichever half refused, flock(1) out here
  /// or vpnctl's own acquire inside -- as this layer's failure. Built in one
  /// place so the two callers cannot drift into describing it differently.
  LockBusyError _lockBusy(String what) => LockBusyError(
        step: stepName,
        what: what,
        lockPath: config.lockPath,
        waited: config.lockWait,
      );

  /// The transport the firewall step must not accept as its own prover.
  String? get primaryTransportId => _primary?.transportId;

  /// The key the primary connection was established against. The prover must
  /// meet the same one: a fresh connection that reached a different machine
  /// says nothing about the machine we just firewalled.
  SshHostKey? get primaryHostKey => _primary?.hostKey;

  Future<void> closePrimary() async {
    final SshConnection? open = _primary;
    _primary = null;
    if (open == null) return;
    try {
      await open.close();
    } on Object catch (_) {
      // A connection we cannot close cleanly is not a provisioning failure;
      // reporting it as one would turn a finished install into a red screen.
      return;
    }
  }

  /// Runs a shell program on the server and hands back whatever it did.
  ///
  /// `sh -c` rather than an argv: everything in commands.dart is a program, not
  /// a command, and control's session quotes each element so the program
  /// reaches the far side in one piece. [RemoteProgram] rather than a String,
  /// because a program can then only have come from a template in commands.dart
  /// with every value quoted on the way in. POSIX sh, because sshd hands us the
  /// login shell and on Debian that may be dash.
  Future<CommandResult> run(RemoteProgram program) async {
    // Read outside the try: no connection is a bug in the step list, not a
    // transport failure, and dressing it as one sends somebody looking at their
    // network.
    final SshSession active = session;
    try {
      return await active.run(<String>['sh', '-c', program.text]);
    } on Object catch (error) {
      throw ProvisionTransportError(step: stepName, cause: error);
    }
  }

  /// [run], but a non-zero exit is the end of the sequence.
  Future<CommandResult> runChecked(
    RemoteProgram program, {
    required String what,
  }) async {
    final CommandResult result = await run(program);
    if (!result.ok) {
      throw ProvisionCommandError(
        step: stepName,
        what: what,
        exitCode: result.exitCode,
        output: result.combined,
      );
    }
    return result;
  }

  /// [runChecked] for a program that invokes vpnctl under the lock.
  ///
  /// Only the one exit status flock owns is treated differently, and it has to
  /// be: `-E 75` exists precisely so that "somebody else is mid-apply" is not
  /// reported as a vpnctl that exited 75 and printed nothing, which is a bug
  /// report about the wrong program.
  Future<CommandResult> runVpnctl(
    RemoteProgram program, {
    required String what,
  }) async {
    final CommandResult result = await run(program);
    if (result.exitCode == lockConflictExit) {
      throw _lockBusy(what);
    }
    if (!result.ok) {
      throw ProvisionCommandError(
        step: stepName,
        what: what,
        exitCode: result.exitCode,
        output: result.combined,
      );
    }
    return result;
  }
}

typedef StepBody = Future<void> Function(ProvisionContext ctx);

/// One named thing that happens to the server.
class ProvisionStep {
  const ProvisionStep({
    required this.name,
    required this.label,
    required this.run,
  });

  /// Stable machine name. Derived from what the step is, never renumbered when
  /// a step is added -- the same contract smoke.sh's check names carry, and for
  /// the same reason: something outside watches one of these across releases.
  final String name;

  /// One line for a human, present tense.
  final String label;

  final StepBody run;
}

/// `key=value` out of a program's stdout. The shell halves of this layer report
/// that way -- `armed=1234`, `head=abc1234`, `bound=10443/tcp` -- because it
/// survives an extra line of noise from a login shell's profile, which a bare
/// value does not.
String? valueOf(String output, String key) {
  for (final String raw in output.split('\n')) {
    final String line = raw.trim();
    if (line.startsWith('$key=')) return line.substring(key.length + 1).trim();
  }
  return null;
}

/// Every value for a repeated key, in order.
List<String> valuesOf(String output, String key) {
  final List<String> found = <String>[];
  for (final String raw in output.split('\n')) {
    final String line = raw.trim();
    if (line.startsWith('$key=')) found.add(line.substring(key.length + 1).trim());
  }
  return found;
}

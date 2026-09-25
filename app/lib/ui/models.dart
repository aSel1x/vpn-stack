import 'dart:async';

import 'package:flutter/foundation.dart';

import '../control/control.dart';
import '../provision/provisioner.dart';
import '../provision/ssh.dart';
import '../provision/step.dart';
import '../tunnel/tunnel.dart';
import 'access.dart';
import 'ports.dart';

/// Plain [ChangeNotifier]s, one per thing a screen watches. No code
/// generation, no store singleton: provider owns the lifetime and `dispose()`
/// is where the connections and subscriptions go.

/// The configured servers, and the persistence around them.
class ServersModel extends ChangeNotifier {
  ServersModel(this._store);

  final ServerStore _store;

  List<ServerProfile> _servers = const <ServerProfile>[];
  bool _loading = true;
  String? _error;

  List<ServerProfile> get servers => _servers;
  bool get loading => _loading;

  /// Set when the list could not be read or written. Shown rather than
  /// swallowed: a save that failed silently looks exactly like a save that
  /// worked, until the app is restarted.
  String? get error => _error;

  Future<void> load() async {
    _loading = true;
    _error = null;
    notifyListeners();
    try {
      _servers = await _store.load();
    } catch (e) {
      _error = describeError(e);
    }
    _loading = false;
    notifyListeners();
  }

  Future<void> add(ServerProfile server) =>
      _mutate(<ServerProfile>[..._servers, server]);

  Future<void> remove(String id) =>
      _mutate(_servers.where((ServerProfile s) => s.id != id).toList());

  /// Records that provisioning finished. Kept here rather than in the
  /// provisioning screen's own model so the flag outlives that screen.
  Future<void> markProvisioned(String id) {
    final DateTime now = DateTime.now().toUtc();
    return _mutate(<ServerProfile>[
      for (final ServerProfile s in _servers)
        if (s.id == id) s.copyWith(provisionedAt: now) else s,
    ]);
  }

  /// Pins the host key somebody just accepted.
  ///
  /// Wired to [ServerAccess]'s recorder, which must not throw -- and does not,
  /// because [_mutate] puts a save failure in [error] instead. A pin that fails
  /// to persist costs one more question next launch; an exception here would
  /// abandon a connection the person had just approved.
  Future<void> rememberHostKey(String id, SshHostKey key) async {
    if (byId(id) == null) {
      // Nothing to pin it to. Happens if the server was removed while a
      // connection to it was still being opened; the connection is about to
      // fail on its own and inventing a record here would resurrect it.
      return;
    }
    await _mutate(<ServerProfile>[
      for (final ServerProfile s in _servers)
        if (s.id == id) s.copyWith(hostKey: key) else s,
    ]);
  }

  /// Drops the pin, so the next connection asks from scratch.
  ///
  /// The deliberate half of the changed-key refusal: the dialog has no accept
  /// button, and this is what somebody does instead once they know why the key
  /// changed.
  Future<void> forgetHostKey(String id) {
    return _mutate(<ServerProfile>[
      for (final ServerProfile s in _servers)
        if (s.id == id) s.withoutHostKey() else s,
    ]);
  }

  ServerProfile? byId(String id) {
    for (final ServerProfile s in _servers) {
      if (s.id == id) {
        return s;
      }
    }
    return null;
  }

  Future<void> _mutate(List<ServerProfile> next) async {
    final List<ServerProfile> previous = _servers;
    _servers = next;
    _error = null;
    notifyListeners();
    try {
      await _store.save(next);
    } catch (e) {
      // Put the list back. Showing a server that is not on disk is how somebody
      // adds the same box twice after a restart.
      _servers = previous;
      _error = describeError(e);
      notifyListeners();
    }
  }
}

/// SSH credentials, for as long as the app is running and no longer.
///
/// Nothing here writes to disk and nothing here expires. Every vpnctl call
/// after provisioning needs the same login -- status, user add, export -- so
/// the credential is held for the process lifetime on purpose, and the forms
/// that collect it say exactly that. They used to say "used once, to
/// provision. Not stored.", which was false about the half people care about:
/// it is not stored, and it IS reused.
///
/// [forget] is the way out, wired to the server list's "Forget SSH
/// credential", and quitting is the other.
class CredentialVault extends ChangeNotifier {
  final Map<String, SshCredential> _byServer = <String, SshCredential>{};

  SshCredential? of(String serverId) => _byServer[serverId];

  bool holds(String serverId) => _byServer.containsKey(serverId);

  void remember(String serverId, SshCredential credential) {
    _byServer[serverId] = credential;
    notifyListeners();
  }

  void forget(String serverId) {
    if (_byServer.remove(serverId) != null) {
      notifyListeners();
    }
  }
}

/// One open conversation with one server.
///
/// Every call is a [Vpnctl] method, which is `flock … vpnctl … --json` and
/// nothing else. This model decides *when* to call and what to keep; it does
/// not parse, build a command line, or know a credential format.
class ServerSession extends ChangeNotifier {
  ServerSession({required this.access});

  /// The server, the credential and the host key policy, as one object that
  /// can only hand back a verified connection. This model never sees the
  /// connector: every path below -- refresh, addUser, removeUser,
  /// setUserEnabled, setProtocol, loadShare -- used to reach `connect()` with
  /// no policy at all through a transport it held directly.
  final ServerAccess access;

  ServerProfile get server => access.server;

  SshConnection? _connection;
  Vpnctl? _vpnctl;
  bool _closed = false;

  ServerStatus? _status;
  List<VpnUser> _users = const <VpnUser>[];
  List<ProtocolEntry> _protocols = const <ProtocolEntry>[];
  bool _busy = false;
  String? _error;
  String? _notice;

  /// Share bundles are cached per user: exporting is not free -- ikev2 writes
  /// three files inside the container and reads them back -- and the connect
  /// card and the share screen ask for the same one.
  final Map<String, ShareBundle> _bundles = <String, ShareBundle>{};
  final Map<String, String> _bundleErrors = <String, String>{};
  final Set<String> _bundlesLoading = <String>{};

  ServerStatus? get status => _status;
  List<VpnUser> get users => _users;
  List<ProtocolEntry> get protocols => _protocols;
  bool get busy => _busy;
  String? get error => _error;

  /// Something that succeeded but is not finished: a convergence still pending,
  /// a port that never bound, an IKEv2 reconcile that could not run. `apply`
  /// only warns about these, so a UI that ignores them reports a green screen
  /// on a server that is not serving.
  String? get notice => _notice;

  ShareBundle? bundleFor(String user) => _bundles[user];
  String? bundleErrorFor(String user) => _bundleErrors[user];
  bool isLoadingBundle(String user) => _bundlesLoading.contains(user);

  Future<bool> refresh() => _guard(() async {
        final Vpnctl control = await _open();
        _status = await control.status();
        _protocols = await control.listProtocols();
        _users = await control.listUsers();
      });

  /// True when the server accepted. False means it refused or could not be
  /// reached and [error] says why -- which the add-user dialog shows next to
  /// the field, because the server owns the name rule and its sentence is the
  /// only one that states it.
  Future<bool> addUser(String name) => _guard(() async {
        final Vpnctl control = await _open();
        final UserMutation result = await control.addUser(name);
        _noteApply(result.apply);
        _users = await control.listUsers();
        _status = await control.status();
      });

  Future<bool> removeUser(String name) => _guard(() async {
        final Vpnctl control = await _open();
        final UserMutation result = await control.removeUser(name);
        _noteApply(result.apply);
        _bundles.remove(name);
        _bundleErrors.remove(name);
        _users = await control.listUsers();
        _status = await control.status();
      });

  Future<bool> setUserEnabled(String name, {required bool enabled}) =>
      _guard(() async {
        final Vpnctl control = await _open();
        final UserEnablement result =
            await control.setUserEnabled(name, enabled: enabled);
        _noteApply(result.apply);
        // Enabling issues a BRAND-NEW ikev2 certificate, so any bundle this app
        // is holding for that user went stale the moment the toggle flipped.
        _bundles.remove(name);
        _bundleErrors.remove(name);
        _users = await control.listUsers();
      });

  Future<bool> setProtocol(String name, {required bool enabled}) =>
      _guard(() async {
        final Vpnctl control = await _open();
        final ProtocolToggle result =
            await control.setProtocol(name, enabled: enabled);
        _noteApply(result.apply);
        _protocols = await control.listProtocols();
        _status = await control.status();
        // What share() emits changed for everybody, so every cached bundle is
        // now a lie.
        _bundles.clear();
        _bundleErrors.clear();
      });

  Future<void> loadShare(String user, {bool force = false}) async {
    if (_bundlesLoading.contains(user)) {
      return;
    }
    if (!force && _bundles.containsKey(user)) {
      return;
    }
    _bundlesLoading.add(user);
    _bundleErrors.remove(user);
    notifyListeners();
    try {
      final Vpnctl control = await _open();
      // No --host: the server resolves it from its own .env, and an address
      // this app invented is one every profile would then carry.
      _bundles[user] = await control.exportUser(user);
    } catch (e) {
      _bundleErrors[user] = _reportable(e);
    }
    _bundlesLoading.remove(user);
    notifyListeners();
  }

  /// The connection every command on this screen runs over, opened once.
  ///
  /// Caching it is right: a detail screen is a dozen vpnctl calls and each one
  /// is a TCP handshake, a key exchange and an authentication if it opens its
  /// own. What it must not do is keep a DEAD one, which is what
  /// [_dropConnection] is for.
  Future<Vpnctl> _open() async {
    final Vpnctl? existing = _vpnctl;
    if (existing != null) {
      return existing;
    }
    // openVerified, via ServerAccess: the key is answered before
    // authentication and re-checked against the policy afterwards.
    final SshConnection opened = await access.open();
    if (_closed) {
      // The screen went away while the handshake was in flight. Closing it here
      // is the only chance: nothing else holds a reference.
      await opened.close();
      throw StateError('the session for ${server.label} was closed');
    }
    _connection = opened;
    final Vpnctl control = Vpnctl(opened.session);
    _vpnctl = control;
    return control;
  }

  /// Throws away the cached connection, so the next command opens a new one.
  ///
  /// The trigger is a transport-level failure and only that. A phone that
  /// changed network, an sshd that timed the session out, a box that rebooted:
  /// the socket will never answer again, and a cached [Vpnctl] over it turns one
  /// lost connection into a screen where every later action fails with no way
  /// back but killing the app. A refusal from vpnctl itself arrived over a
  /// connection that plainly works, and tearing that down would make one
  /// rejected user name cost a reconnect.
  void _dropConnection() {
    final SshConnection? dead = _connection;
    _connection = null;
    _vpnctl = null;
    if (dead != null) {
      // Not awaited, and its failure swallowed. This runs on the failure path
      // of whatever the caller was doing; the socket is already suspect, and a
      // close that also fails changes nothing about what has to be said.
      unawaited(dead.close().catchError((Object _) {}));
    }
  }

  /// The sentence to show for [error], dropping the connection first when the
  /// failure was the connection.
  ///
  /// Both the action guard and the share loader go through here, because a
  /// transport failure can arrive on either: `loadShare` is the one path that
  /// does not use [_guard], and a share export that loses the connection would
  /// otherwise leave the session dead while every button still looked live.
  ///
  /// One exception type covers it, and that is a property of the layer below
  /// rather than an assumption: `Vpnctl._run` catches everything `session.run`
  /// throws -- deliberately catch-all, so a closed session's own failure is
  /// included -- and rethrows it as [VpnctlTransportError]. The failures that
  /// are NOT that (a refused host key, a credential the server would not take)
  /// come out of `access.open()`, which only runs when nothing is cached, so
  /// there is no dead connection to drop.
  String _reportable(Object error) {
    final String described = describeError(error);
    if (error is! VpnctlTransportError) {
      return described;
    }
    _dropConnection();
    // No reassurance about what did or did not happen on the server. The
    // sentence above already says that a command with no exit status leaves
    // "whether it ran at all" unknown, and a soothing clause here would
    // contradict it -- `user add` writes users.json before it converges.
    return '$described\n\n'
        'The connection to ${server.label} has been closed; the next action '
        'opens a new one.';
  }

  void _noteApply(ApplyResult? apply) {
    if (apply == null) {
      return;
    }
    final List<String> problems = <String>[];
    if (apply.convergePending) {
      problems.add(
        'A new config is on disk but no container is running it yet. Until an '
        'apply converges, the server is still serving the previous keys and a '
        'profile exported now will not connect.',
      );
    }
    final List<String>? ready = apply.ready;
    if (ready != null && !apply.portsBound) {
      problems.addAll(ready);
    }
    final Ikev2Reconcile? reconcile = apply.ikev2Reconcile;
    if (reconcile != null) {
      final String? skipped = reconcile.skipped;
      if (skipped != null) {
        problems.add('IKEv2 certificates were not reconciled: $skipped');
      }
      if (reconcile.failed.isNotEmpty) {
        problems.add(
          'IKEv2 could not issue or revoke for: '
          '${reconcile.failed.join(', ')}. A failed revoke means that '
          'certificate still connects.',
        );
      }
    }
    if (apply.unknownKeys.isNotEmpty) {
      problems.add(
        'The server sent keys this app does not know '
        '(${apply.unknownKeys.join(', ')}). It is newer than this app; the '
        'command itself worked.',
      );
    }
    _notice = problems.isEmpty ? null : problems.join('\n\n');
  }

  /// Returns whether the command ran and succeeded.
  ///
  /// A caller that only draws the banner can ignore it; the add-user dialog
  /// cannot, because it has to decide whether to close. False with [error]
  /// still null means it never ran -- something else held the session -- and
  /// nothing here invents a message for that, or the banner would show a
  /// refusal for a command the server never saw.
  Future<bool> _guard(Future<void> Function() body) async {
    if (_busy) {
      return false;
    }
    _busy = true;
    _error = null;
    _notice = null;
    notifyListeners();
    try {
      await body();
    } catch (e) {
      _error = _reportable(e);
    }
    _busy = false;
    notifyListeners();
    return _error == null;
  }

  @override
  void dispose() {
    _closed = true;
    _dropConnection();
    super.dispose();
  }
}

/// One provisioning run, from the plan to whatever it ended as.
///
/// The plan is [Provisioner.steps] -- the same list the runner walks, not a
/// copy of it -- so a step added to `provision/steps.dart` appears here with no
/// change on this side.
class ProvisionRun extends ChangeNotifier {
  ProvisionRun({required this.access}) : _provisioner = access.provisioner();

  final ServerAccess access;

  ServerProfile get server => access.server;

  final Provisioner _provisioner;

  final Map<String, StepPhase> _phase = <String, StepPhase>{};
  final Map<String, String> _message = <String, String>{};

  bool _started = false;
  bool _finished = false;
  String? _failure;
  ProvisionResult? _result;

  List<ProvisionStep> get steps => _provisioner.steps;
  bool get started => _started;
  bool get finished => _finished;
  bool get running => _started && !_finished;

  /// The failure text, verbatim. Null while it is still going and after it
  /// succeeded.
  String? get failure => _failure;

  bool get succeeded => _finished && _failure == null && _result != null;

  /// What the run learned: the distribution, the cloned commit, the deadman's
  /// pid, which ports came up. Empty until it finishes.
  Map<String, String> get facts => _result?.facts ?? const <String, String>{};

  /// Null for a step that has not reported yet.
  StepPhase? phaseOf(String step) => _phase[step];

  String? messageOf(String step) => _message[step];

  Future<void> start() async {
    if (_started) {
      return;
    }
    _started = true;
    _failure = null;
    notifyListeners();
    try {
      _result = await _provisioner.run(onEvent: _onEvent);
    } catch (e) {
      // The runner stops on the first failure and rethrows the step's own
      // exception, which already says what happened in words somebody can act
      // on. The failed step is marked by the event that preceded this.
      _failure = describeError(e);
    }
    _finished = true;
    notifyListeners();
  }

  void _onEvent(ProvisionEvent event) {
    _phase[event.step] = event.phase;
    if (event.message.isNotEmpty) {
      // The latest line wins: `progress` fires repeatedly inside a step that is
      // still going, and that movement is the whole reason it fires.
      _message[event.step] = event.message;
    }
    notifyListeners();
  }
}

/// The tunnel, as the widgets see it.
///
/// A thin wrapper on purpose: every decision about what "connected" means
/// belongs to [TunnelController], and duplicating any of it here would let the
/// UI show a state the engine never reported.
class TunnelModel extends ChangeNotifier {
  TunnelModel(this._controller) {
    _subscription = _controller.statusStream.listen((TunnelStatus next) {
      _status = next;
      notifyListeners();
    });
  }

  final TunnelController _controller;
  late final StreamSubscription<TunnelStatus> _subscription;

  TunnelStatus _status = TunnelStatus.idle;

  TunnelStatus get status => _status;

  /// True only when the tunnel this profile describes is the one that is up.
  bool isUpFor(String profileId) =>
      _status.isUp && _status.profileId == profileId;

  bool isBusyFor(String profileId) =>
      _status.isBusy && _status.profileId == profileId;

  bool isFailedFor(String profileId) =>
      _status.stage == TunnelStage.failed && _status.profileId == profileId;

  Future<void> connect(TunnelProfile profile) async {
    try {
      await _controller.connect(profile);
    } catch (e) {
      // The controller has already published a failed status carrying this
      // text; rethrowing would only turn a button press into an unhandled
      // error, and there is nowhere better for it to go.
      if (_status.stage != TunnelStage.failed) {
        _status = TunnelStatus(
          TunnelStage.failed,
          profileId: profile.id,
          message: describeError(e),
        );
        notifyListeners();
      }
    }
  }

  Future<void> disconnect() async {
    try {
      await _controller.disconnect();
    } catch (e) {
      _status = TunnelStatus(
        TunnelStage.failed,
        profileId: _status.profileId,
        message: describeError(e),
      );
      notifyListeners();
    }
  }

  @override
  void dispose() {
    unawaited(_subscription.cancel());
    unawaited(_controller.dispose());
    super.dispose();
  }
}

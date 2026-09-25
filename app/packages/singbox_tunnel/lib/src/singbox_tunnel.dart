// The engine behind TunnelController, on both platforms that have one.
//
// Commands go out over a MethodChannel; status comes back over an EventChannel,
// so the tunnel's state arrives as a stream instead of being polled. Polling
// would have to pick an interval, and every interval is either a busy loop or a
// window in which the UI shows a tunnel that is already down.
//
// One controller for Android and iOS, because the channel contract is the same
// on both -- five commands, one status event shape -- and nothing above it has
// to care which platform answered. What is NOT the same is the prose in a
// failure, which is why the controller is handed a TunnelPlatformText rather
// than writing the words itself: see platform_text.dart.

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../tunnel_api.dart';
import 'channels.dart';
import 'platform_text.dart';

/// Turns a profile's share URIs into the sing-box configuration JSON the engine
/// is started with.
///
/// Injected rather than imported. `app/lib/config/` is the single definition of
/// that format and it lives in the app, which this package cannot depend on
/// (app -> package -> app is a cycle); duplicating it here is the exact drift
/// app/README.md refuses. So the package takes a config STRING and never builds
/// one, and `main.dart` supplies the builder.
typedef SingBoxConfigBuilder = String Function(TunnelProfile profile);

/// sing-box through libbox: a `VpnService` on Android, a
/// `NEPacketTunnelProvider` on iOS.
///
/// Reports [TunnelStage.connected] on exactly one condition: the platform said
/// so, and it only says so after libbox's `CommandServer.startOrReloadService`
/// returned without throwing. That call is synchronous all the way down --
/// sing-box v1.14.0 `daemon/started_service.go:250` returns nil only after
/// `instance.Start()` has succeeded, which is what calls back into `openTun` and
/// takes the file descriptor. There is no code path here that reports connected
/// on a timer, on an optimistic guess, or on an error it decided to tolerate.
class SingboxTunnel extends BaseTunnelController {
  /// [buildConfig] is called on [connect] and its output is handed to the
  /// engine verbatim. If it throws, the tunnel fails with that message and
  /// nothing is started.
  ///
  /// [platform] is the wording of a failure, not a switch over behaviour: the
  /// code paths are identical on Android and iOS. It is injectable because
  /// `defaultTargetPlatform` cannot be moved except by a debug override, and a
  /// test that asserts an iPhone's message is not running on one.
  SingboxTunnel(this._buildConfig, {TunnelPlatformText? platform})
      : _platform =
            platform ?? TunnelPlatformText.forPlatform(defaultTargetPlatform) {
    _events = _statusChannel.receiveBroadcastStream().listen(
          _onPlatformStatus,
          onError: _onPlatformError,
        );
  }

  final SingBoxConfigBuilder _buildConfig;

  final TunnelPlatformText _platform;

  static const MethodChannel _commands = MethodChannel(commandChannelName);
  static const EventChannel _statusChannel = EventChannel(statusChannelName);

  /// How long `connect` waits for the platform to settle on connected or
  /// failed. libbox brings the whole box up inside this call -- TLS, QUIC, the
  /// tun -- and a cold start on a slow phone is seconds, not milliseconds. On
  /// expiry this fails loudly; it never falls through to connected.
  static const Duration _connectTimeout = Duration(seconds: 45);

  static const Duration _disconnectTimeout = Duration(seconds: 20);

  late final StreamSubscription<dynamic> _events;

  /// Which profile the platform's statuses are about. The platform does not
  /// know profile ids -- it was handed a config string -- so the id is stamped
  /// on this side, from the last profile this controller was asked to connect.
  String? _activeProfileId;

  /// Waiters for the next terminal status. A list rather than a single slot
  /// because a UI can call connect twice before the first settles, and dropping
  /// the earlier future would hang that caller for ever.
  final List<Completer<TunnelStatus>> _settlers = <Completer<TunnelStatus>>[];

  @override
  Future<void> connect(TunnelProfile profile) async {
    if (!profile.isConnectable) {
      _fail(
        profile.id,
        'Nothing to connect with: ${profile.label} (${profile.host}) carries no '
        'share URIs. The server issues them with `vpnctl user export`; a profile '
        'that has none was stored before its credentials were fetched.',
      );
    }

    _activeProfileId = profile.id;
    emit(TunnelStatus(TunnelStage.connecting, profileId: profile.id));

    final String config;
    try {
      config = _buildConfig(profile);
    } on Object catch (error) {
      _fail(
        profile.id,
        'Could not build a sing-box configuration for ${profile.label} from its '
        '${profile.importUris.length} share URI(s): $error',
      );
    }

    if (!await _ensurePermission(profile.id)) {
      _fail(
        profile.id,
        '${_platform.osName} ${_platform.consentDenied} for ${profile.label}. '
        'Without it no tunnel was established and no traffic is being routed. '
        '${_platform.consentDetail}',
      );
    }

    // Registered before `start` so a platform that settles immediately cannot
    // land its event in the gap between the call and the wait.
    final Future<TunnelStatus> settled = _nextSettled();

    try {
      await _commands.invokeMethod<void>('start', <String, Object?>{
        'config': config,
        'label': profile.label,
      });
    } on PlatformException catch (error) {
      _fail(profile.id, _describe('start', error));
    } on MissingPluginException catch (error) {
      _fail(profile.id, _describeMissing(error));
    }

    // A status the platform sent is already on the stream; one this timeout
    // manufactures is not, and has to be put there so a caller that did not
    // await connect() still learns the tunnel never came up.
    bool timedOut = false;
    final TunnelStatus result = await settled.timeout(
      _connectTimeout,
      onTimeout: () {
        timedOut = true;
        return TunnelStatus(
          TunnelStage.failed,
          profileId: profile.id,
          message: '${_platform.startedProcess} was started but reported '
              'neither success nor failure within ${_connectTimeout.inSeconds}s. '
              'The tunnel may or may not be up; this build will not guess. '
              '${_platform.logHint} carries what libbox said.',
        );
      },
    );

    if (result.stage != TunnelStage.connected) {
      if (timedOut) {
        emit(result);
      }
      throw StateError(result.message ??
          'The tunnel did not come up and the platform gave no reason.');
    }
  }

  @override
  Future<void> disconnect() async {
    // Tearing down nothing is not an error, and must not become one by waiting
    // for a status change that nobody is going to send.
    if (status.stage == TunnelStage.disconnected) {
      emit(TunnelStatus.idle);
      return;
    }

    final Future<TunnelStatus> settled = _nextSettled();

    try {
      await _commands.invokeMethod<void>('stop');
    } on PlatformException catch (error) {
      _fail(_activeProfileId, _describe('stop', error));
    } on MissingPluginException catch (error) {
      _fail(_activeProfileId, _describeMissing(error));
    }

    bool timedOut = false;
    final TunnelStatus result = await settled.timeout(
      _disconnectTimeout,
      onTimeout: () {
        timedOut = true;
        return TunnelStatus(
          TunnelStage.failed,
          profileId: _activeProfileId,
          message: 'Asked ${_platform.osName} to stop the tunnel and it did not '
              'confirm within ${_disconnectTimeout.inSeconds}s. Treat the tunnel '
              'as still up: reporting it down here would be the one lie this '
              'layer must not tell. ${_platform.groundTruth}',
        );
      },
    );

    if (result.stage == TunnelStage.failed) {
      if (timedOut) {
        emit(result);
      }
      throw StateError(result.message ?? 'The tunnel did not stop.');
    }
  }

  @override
  Future<void> dispose() async {
    await _events.cancel();
    await super.dispose();
  }

  /// True when the system has already consented to this app opening a tunnel,
  /// or consented in response to the sheet this raises.
  ///
  /// `VpnService.prepare()` returns null when consent is already on file and an
  /// Intent otherwise, and that Intent can only be shown from an Activity; iOS
  /// has no permission API at all, so the plugin reads consent as "a VPN
  /// configuration for this app's extension is installed" and asks by saving
  /// one, which is what raises the approval sheet. Both platforms handle both
  /// paths; what must not happen is the third one -- never asking, and running
  /// a service that silently establishes nothing.
  Future<bool> _ensurePermission(String profileId) async {
    try {
      if (await _commands.invokeMethod<bool>('prepare') ?? false) {
        return true;
      }
      return await _commands.invokeMethod<bool>('requestPermission') ?? false;
    } on PlatformException catch (error) {
      _fail(profileId, _describe('requestPermission', error));
    } on MissingPluginException catch (error) {
      _fail(profileId, _describeMissing(error));
    }
  }

  Future<TunnelStatus> _nextSettled() {
    final Completer<TunnelStatus> completer = Completer<TunnelStatus>();
    _settlers.add(completer);
    return completer.future;
  }

  void _settle(TunnelStatus terminal) {
    if (_settlers.isEmpty) {
      return;
    }
    final List<Completer<TunnelStatus>> waiting =
        List<Completer<TunnelStatus>>.of(_settlers);
    _settlers.clear();
    for (final Completer<TunnelStatus> completer in waiting) {
      completer.complete(terminal);
    }
  }

  void _onPlatformStatus(Object? event) {
    final TunnelStatus next = decodeStatus(event, _activeProfileId, _platform);
    emit(next);
    if (next.stage != TunnelStage.connecting) {
      _settle(next);
    }
  }

  void _onPlatformError(Object error) {
    // Never swallowed into a neutral status. An EventChannel error means the
    // status feed itself broke, so what this controller reports about the
    // tunnel from here on is unreliable -- which is a failure, not an idle.
    final TunnelStatus next = TunnelStatus(
      TunnelStage.failed,
      profileId: _activeProfileId,
      message: 'The ${_platform.osName} status channel failed: $error',
    );
    emit(next);
    _settle(next);
  }

  /// The platform's own words, unwrapped.
  ///
  /// Both platform sides write their failures as prose that names what is
  /// missing and what to do about it -- `no_activity` says to bring the app to
  /// the foreground, `no_session` says the extension's bundle identifier names a
  /// target that is not a NEPacketTunnelProvider -- and [TunnelStatus.message]
  /// is shown verbatim. A frame in front of that sentence added nothing on
  /// Android and, when the frame said "Android", put the wrong operating system
  /// in front of the right diagnosis on iOS.
  ///
  /// The code and the method are the fallback rather than the frame: a platform
  /// that fails with no message leaves nothing else to show, and `(no message)`
  /// on its own names neither the call that failed nor where to look it up.
  String _describe(String method, PlatformException error) {
    final String extra = error.details == null ? '' : ' -- ${error.details}';
    final String? detail = error.message;
    if (detail == null || detail.isEmpty) {
      return '${_platform.osName} refused `$method` with code '
          '"${error.code}" and no message. Nothing here can say more than '
          'that; ${_platform.logHint} carries the rest.$extra';
    }
    return '$detail$extra';
  }

  String _describeMissing(MissingPluginException error) =>
      'The singbox_tunnel platform channel is not registered on this build: '
      '$error. ${_platform.unregistered} Nothing was connected.';

  /// Emits [TunnelStage.failed] and throws with the same text, which is what
  /// TunnelController.connect promises: the awaiting caller gets an exception
  /// and a caller that did not await sees it on the stream.
  Never _fail(String? profileId, String message) {
    emit(TunnelStatus(
      TunnelStage.failed,
      profileId: profileId,
      message: message,
    ));
    throw StateError(message);
  }
}

/// Decodes one platform status event.
///
/// Separate from the controller so the channel contract reads in one place, and
/// so it can be tested without a channel at all. Every shape it cannot read
/// becomes [TunnelStage.failed] carrying the raw event: an unknown stage string
/// is a version skew between this Dart and the platform code, and the one answer
/// that must never come out of a skew is "connected".
TunnelStatus decodeStatus(
  Object? event,
  String? profileId,
  TunnelPlatformText platform,
) {
  if (event is! Map<Object?, Object?>) {
    return TunnelStatus(
      TunnelStage.failed,
      profileId: profileId,
      message: 'The ${platform.osName} side sent a status this build cannot '
          'read: $event',
    );
  }

  final Object? message = event['message'];
  final String? text = message is String && message.isNotEmpty ? message : null;

  switch (event['stage']) {
    case stageDisconnected:
      return TunnelStatus(
        TunnelStage.disconnected,
        profileId: profileId,
        message: text,
      );
    case stageConnecting:
      return TunnelStatus(
        TunnelStage.connecting,
        profileId: profileId,
        message: text,
      );
    case stageConnected:
      return TunnelStatus(
        TunnelStage.connected,
        profileId: profileId,
        message: text,
      );
    case stageFailed:
      return TunnelStatus(
        TunnelStage.failed,
        profileId: profileId,
        message: text ??
            'The ${platform.osName} side reported failure without saying why. '
                'That is a bug in ${platform.engineClass}, which is required to '
                'name what broke.',
      );
    default:
      return TunnelStatus(
        TunnelStage.failed,
        profileId: profileId,
        message: 'Unknown tunnel stage "${event['stage']}" from the '
            '${platform.osName} side. This Dart and that ${platform.language} '
            'disagree about the channel contract; refusing to guess which state '
            'the tunnel is in.',
      );
  }
}

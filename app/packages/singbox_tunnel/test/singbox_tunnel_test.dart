// The state machine between a Connect button and libbox.
//
// Its worst reachable failure is reporting "Connected" with no tunnel up:
// somebody believes it, routes their traffic through nothing, and finds out
// later. Every assertion here is ultimately about that -- the controller may
// only reach [TunnelStage.connected] because the platform said so, and every
// other outcome, including a timeout and a channel that is not registered at
// all, has to arrive as a failure carrying text a person can act on.
//
// The platform side is faked: a MethodChannel handler that records what was
// asked of it and answers what the test wants, and an EventChannel whose events
// this file sends by hand. So the Dart half is exercised end to end with no
// device, no emulator and no libbox, which is the only half a machine with no
// Android SDK can judge at all.

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:singbox_tunnel/src/channels.dart';
import 'package:singbox_tunnel/src/platform_text.dart';
import 'package:singbox_tunnel/src/singbox_tunnel.dart';
import 'package:singbox_tunnel/tunnel_api.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const TunnelProfile profile = TunnelProfile(
    id: 'srv-1',
    label: 'stockholm',
    host: '203.0.113.7',
    importUris: <String>['vless://u@203.0.113.7:10443?sni=www.apple.com'],
  );

  /// A configuration the engine would accept. Its content is never inspected by
  /// this package -- `app/lib/config/` owns that format -- so the tests only
  /// care that whatever the builder returned is what `start` was handed.
  const String config = '{"outbounds":[{"type":"vless"}]}';

  SingboxTunnel tunnelFor(
    _FakePlatform platform, {
    TunnelPlatformText text = TunnelPlatformText.android,
    SingBoxConfigBuilder? buildConfig,
  }) {
    final SingboxTunnel tunnel = SingboxTunnel(
      buildConfig ?? (TunnelProfile _) => config,
      platform: text,
    );
    addTearDown(tunnel.dispose);
    return tunnel;
  }

  group("connected is only ever the platform's word", () {
    test('a successful start is not connected until a status says so', () async {
      // The whole point of the settle-and-wait shape. `start` returning without
      // throwing means the call was accepted, not that a TUN descriptor exists;
      // libbox reports the second separately and this waits for it.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await pumpEventQueue();

      expect(attempt.done, isFalse,
          reason: 'connect() completed on the strength of `start` returning');
      expect(tunnel.status.stage, TunnelStage.connecting);

      platform.emit(<Object?, Object?>{'stage': stageConnected});
      await pumpEventQueue();
      await attempt.settled;

      expect(attempt.thrown, isNull);
      expect(tunnel.status.stage, TunnelStage.connected);
      expect(tunnel.status.profileId, profile.id);
    });

    test('the config the builder returned is what start is handed', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await pumpEventQueue();
      platform.emit(<Object?, Object?>{'stage': stageConnected});
      await pumpEventQueue();
      await attempt.settled;

      final MethodCall start =
          platform.calls.firstWhere((MethodCall c) => c.method == 'start');
      expect(start.arguments, <String, Object?>{
        'config': config,
        'label': profile.label,
      });
    });

    test('a disconnected status while connecting fails the attempt', () async {
      // The platform giving up without a reason still has to settle the
      // waiting connect(), or the caller hangs until the 45s timeout and the
      // UI shows a spinner over a tunnel that is already gone.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await pumpEventQueue();
      platform.emit(<Object?, Object?>{'stage': stageDisconnected});
      await pumpEventQueue();
      await attempt.settled;

      expect(attempt.thrown, isA<StateError>());
      expect(tunnel.status.stage, TunnelStage.disconnected);
    });
  });

  group("failures carry the platform's own words", () {
    test('a PlatformException from start is passed through unwrapped', () async {
      // Both platform sides write their refusals as prose naming what is
      // missing and what to do about it, and TunnelStatus.message is shown
      // verbatim. A frame in front of it ("Android refused `start`") added
      // nothing on Android and named the wrong operating system on iOS.
      const String refusal =
          'Android\'s VPN consent dialog can only be shown from an Activity and '
          'this plugin is not attached to one. Bring the app to the foreground '
          'and try again; nothing was started.';
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] =
            PlatformException(code: 'no_activity', message: refusal);
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await attempt.settled;

      expect(tunnel.status.stage, TunnelStage.failed);
      expect(tunnel.status.message, refusal);
      expect(attempt.message, refusal);
    });

    test('details are appended, and nothing else is', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = PlatformException(
          code: 'service_start_failed',
          message: 'libbox refused the configuration.',
          details: 'json: unknown field "tls_fragment"',
        );
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await attempt.settled;

      expect(
        tunnel.status.message,
        'libbox refused the configuration. -- json: unknown field '
        '"tls_fragment"',
      );
    });

    test('a refusal with no message falls back to the code', () async {
      // The only case where the method name and the code are worth printing:
      // there is nothing else to show, and "(no message)" on its own names
      // neither the call that failed nor where to look for more.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = PlatformException(code: 'unknown');
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await attempt.settled;

      expect(attempt.message, contains('`start`'));
      expect(attempt.message, contains('"unknown"'));
      expect(attempt.message, contains('adb logcat'));
    });

    test('a broken status feed is a failure, not an idle', () async {
      // An error on the EventChannel means the status feed itself broke, so
      // everything this controller would say about the tunnel afterwards is
      // unreliable. Reporting that as disconnected would be a guess.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await pumpEventQueue();
      platform.breakFeed(code: 'sink_closed', message: 'The sink is gone.');
      await pumpEventQueue();
      await attempt.settled;

      expect(tunnel.status.stage, TunnelStage.failed);
      expect(tunnel.status.message, contains('status channel failed'));
      expect(tunnel.status.message, contains('The sink is gone.'));
    });

    test('an unregistered channel says so, and says what to do', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = MissingPluginException(
            'No implementation found for method prepare on channel '
            '$commandChannelName');
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await attempt.settled;

      expect(tunnel.status.stage, TunnelStage.failed);
      expect(attempt.message, contains('is not registered on this build'));
      expect(attempt.message, contains('a hot restart does not register'));
      expect(platform.methods, <String>['prepare'],
          reason: 'went on to start a tunnel over a channel that is not there');
    });
  });

  group('nothing is started that cannot be', () {
    test('a profile with no share URIs fails before any channel call', () async {
      const TunnelProfile empty = TunnelProfile(
        id: 'srv-2',
        label: 'fresh',
        host: '203.0.113.9',
        importUris: <String>[],
      );
      final _FakePlatform platform = _FakePlatform();
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(empty));

      await attempt.settled;

      expect(tunnel.status.stage, TunnelStage.failed);
      expect(attempt.message, contains('carries no share URIs'));
      expect(platform.methods, isEmpty);
      expect(tunnel.status.profileId, empty.id);
    });

    test('a builder that throws starts nothing', () async {
      // The configuration is built on this side, so a URI the config layer
      // cannot parse has to fail here -- before the VPN consent sheet, and
      // certainly before a service is asked to run an empty config.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true;
      final SingboxTunnel tunnel = tunnelFor(
        platform,
        buildConfig: (TunnelProfile _) =>
            throw const FormatException('unsupported scheme "ss"'),
      );
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await attempt.settled;

      expect(tunnel.status.stage, TunnelStage.failed);
      expect(attempt.message, contains('unsupported scheme "ss"'));
      expect(attempt.message, contains('1 share URI(s)'));
      expect(platform.methods, isEmpty);
    });

    test('a refused consent fails without asking for a tunnel', () async {
      // `false` from either call is a person saying no. Starting the service
      // anyway would establish nothing and report it as running.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = false
        ..answers['requestPermission'] = false;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await attempt.settled;

      expect(tunnel.status.stage, TunnelStage.failed);
      expect(attempt.message, contains('did not grant VPN permission'));
      expect(platform.methods, <String>['prepare', 'requestPermission']);
    });

    test('consent granted at the sheet goes on to start', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = false
        ..answers['requestPermission'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await pumpEventQueue();
      platform.emit(<Object?, Object?>{'stage': stageConnected});
      await pumpEventQueue();
      await attempt.settled;

      expect(attempt.thrown, isNull);
      expect(platform.methods,
          <String>['prepare', 'requestPermission', 'start']);
    });
  });

  group('two callers waiting on one outcome', () {
    // A UI can call connect twice before the first settles -- a double tap, or
    // a screen rebuilt while a connection is in flight. Both futures must
    // settle, because a dropped one hangs its caller for ever, and the second
    // event must not complete an already-completed waiter.
    test('both succeed, and a later event completes neither twice', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt first = _Attempt(tunnel.connect(profile));
      final _Attempt second = _Attempt(tunnel.connect(profile));

      await pumpEventQueue();
      platform.emit(<Object?, Object?>{'stage': stageConnected});
      await pumpEventQueue();
      await first.settled;
      await second.settled;

      expect(first.thrown, isNull);
      expect(second.thrown, isNull);

      // Completing a Completer twice throws, so a second terminal event
      // arriving on a waiter list that was not cleared would surface here as an
      // uncaught error rather than a quiet no-op.
      platform.emit(<Object?, Object?>{'stage': stageDisconnected});
      await pumpEventQueue();

      expect(tunnel.status.stage, TunnelStage.disconnected);
    });

    test('both fail with the same text', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt first = _Attempt(tunnel.connect(profile));
      final _Attempt second = _Attempt(tunnel.connect(profile));

      await pumpEventQueue();
      platform.emit(<Object?, Object?>{
        'stage': stageFailed,
        'message': 'libbox: bind: address already in use',
      });
      await pumpEventQueue();
      await first.settled;
      await second.settled;

      expect(first.message, 'libbox: bind: address already in use');
      expect(second.message, first.message);
    });
  });

  group('disconnect', () {
    test('tearing down nothing asks the platform nothing', () async {
      final _FakePlatform platform = _FakePlatform();
      final SingboxTunnel tunnel = tunnelFor(platform);

      await tunnel.disconnect();

      expect(platform.methods, isEmpty);
      expect(tunnel.status.stage, TunnelStage.disconnected);
    });

    test('a running tunnel is stopped and waits for the platform', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null
        ..answers['stop'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt connecting = _Attempt(tunnel.connect(profile));
      await pumpEventQueue();
      platform.emit(<Object?, Object?>{'stage': stageConnected});
      await pumpEventQueue();
      await connecting.settled;

      final _Attempt stopping = _Attempt(tunnel.disconnect());
      await pumpEventQueue();

      expect(stopping.done, isFalse,
          reason: 'reported the tunnel down before the platform confirmed');

      platform.emit(<Object?, Object?>{'stage': stageDisconnected});
      await pumpEventQueue();
      await stopping.settled;

      expect(stopping.thrown, isNull);
      expect(tunnel.status.stage, TunnelStage.disconnected);
      expect(platform.methods.last, 'stop');
    });
  });

  group('the timeouts fail rather than fall through', () {
    // These need the fake clock: the windows are 45s and 20s of real time, and
    // testWidgets runs its body inside FakeAsync, so the elapse is free.
    testWidgets('connect fails when the platform never settles',
        (WidgetTester tester) async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await tester.pump();
      expect(tunnel.status.stage, TunnelStage.connecting);

      await tester.pump(const Duration(seconds: 44));
      expect(attempt.done, isFalse,
          reason: 'gave up before the window it promises');

      await tester.pump(const Duration(seconds: 2));
      await attempt.settled;

      expect(tunnel.status.stage, TunnelStage.failed,
          reason: 'a silent platform must never read as connected');
      expect(attempt.message, contains('45s'));
      expect(attempt.message, contains('will not guess'));
    });

    testWidgets('a timeout is published, not only thrown',
        (WidgetTester tester) async {
      // The status the timeout manufactures is the one status no platform sent,
      // so unless it is emitted a caller that did not await connect() -- a
      // button handler that fired and forgot -- would sit on `connecting` for
      // ever.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final List<TunnelStage> seen = <TunnelStage>[];
      final _Attempt attempt = _Attempt(tunnel.connect(profile));
      tunnel.statusStream.listen((TunnelStatus s) => seen.add(s.stage));

      await tester.pump(const Duration(seconds: 46));
      await attempt.settled;

      expect(seen, contains(TunnelStage.failed));
    });

    testWidgets('an unconfirmed stop is not reported as down',
        (WidgetTester tester) async {
      // The one lie this layer must not tell. If Android was asked to stop and
      // did not confirm, the tunnel may still be carrying traffic, and a UI
      // showing "disconnected" over a live tunnel is how somebody sends
      // plaintext believing otherwise.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null
        ..answers['stop'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt connecting = _Attempt(tunnel.connect(profile));
      await tester.pump();
      platform.emit(<Object?, Object?>{'stage': stageConnected});
      await tester.pump();
      await connecting.settled;

      final _Attempt stopping = _Attempt(tunnel.disconnect());
      await tester.pump(const Duration(seconds: 21));
      await stopping.settled;

      expect(stopping.thrown, isA<StateError>());
      expect(stopping.message, contains('Treat the tunnel as still up'));
      expect(tunnel.status.stage, TunnelStage.failed);
      expect(tunnel.status.isUp, isFalse);
    });
  });

  group('forgetting a server takes this device off it', () {
    // Deleting a server in the app used to reach no native teardown at all, so
    // the NETunnelProviderManager installed at the first connect stayed under
    // Settings > General > VPN & Device Management -- and flipping it started
    // the extension from a saved configuration carrying a VLESS UUID or a
    // Hysteria2 password, for a server the app no longer knew about.
    //
    // None of this revokes anything. The credentials stay valid until
    // `vpn user rm` runs on the server; what these assert is that this
    // DEVICE's copy goes.
    test('removes the profile the system installed', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['removeProfile'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);

      expect(await tunnel.forgetProfile(profile.id), isNull);

      expect(platform.methods, contains('removeProfile'));
    });

    test('stops a live tunnel first, because the stored config is the credential',
        () async {
      // Android deletes the persisted start request when the service stops and
      // at no other time, so a tunnel left running is the whole content of a
      // share URI left in clear on a device whose owner just deleted the
      // server.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null
        ..answers['stop'] = null
        ..answers['removeProfile'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt connecting = _Attempt(tunnel.connect(profile));
      await pumpEventQueue();
      platform.emit(<Object?, Object?>{'stage': stageConnected});
      await pumpEventQueue();
      await connecting.settled;

      final Future<String?> forgetting = tunnel.forgetProfile(profile.id);
      await pumpEventQueue();
      platform.emit(<Object?, Object?>{'stage': stageDisconnected});
      await pumpEventQueue();

      expect(await forgetting, isNull);
      // Both halves: that it stopped at all, and that it stopped BEFORE the
      // profile went. `indexOf` alone would pass on a -1 for a stop that never
      // happened, which is the mutation this test exists to catch.
      expect(platform.methods, contains('stop'));
      expect(platform.methods, contains('removeProfile'));
      expect(platform.methods.indexOf('stop'),
          lessThan(platform.methods.indexOf('removeProfile')));
    });

    test('leaves the device copy alone when it belongs to another server',
        () async {
      // One configuration per device -- iOS installs a single manager, the
      // Android service keeps one start request -- and it belongs to whatever
      // was connected last. Removing it here would take a different server's
      // credential, and its running tunnel, with it.
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null
        ..answers['removeProfile'] = null;
      final SingboxTunnel tunnel = tunnelFor(platform);
      final _Attempt connecting = _Attempt(tunnel.connect(profile));
      await pumpEventQueue();
      platform.emit(<Object?, Object?>{'stage': stageConnected});
      await pumpEventQueue();
      await connecting.settled;

      expect(await tunnel.forgetProfile('some-other-server'), isNull);

      expect(platform.methods, isNot(contains('removeProfile')));
      expect(platform.methods, isNot(contains('stop')));
    });

    test('a platform with nothing of the kind does not fail the removal',
        () async {
      // Android answers `notImplemented`, which arrives here as a
      // MissingPluginException: it installs no system profile. Forgetting the
      // server is the person's decision and a tunnel layer with nothing to do
      // may not veto it, so this is a no-op and not a failure.
      final _FakePlatform platform = _FakePlatform()
        ..answers['removeProfile'] =
            MissingPluginException('No implementation found for removeProfile');
      final SingboxTunnel tunnel = tunnelFor(platform);

      expect(await tunnel.forgetProfile(profile.id), isNull);
    });

    test('a profile the system would not delete is reported, not swallowed',
        () async {
      // The one part of a removal that is not cosmetic: the app's record is
      // gone and the credential is not. The platform's own sentence comes back
      // for the UI to show, because it names where the row still is.
      final _FakePlatform platform = _FakePlatform()
        ..answers['removeProfile'] = PlatformException(
          code: 'remove_failed',
          message: 'iOS refused to remove this app\'s VPN profile. It is still '
              'listed under Settings > General > VPN & Device Management.',
        );
      final SingboxTunnel tunnel =
          tunnelFor(platform, text: TunnelPlatformText.ios);

      final String? left = await tunnel.forgetProfile(profile.id);

      expect(left, isNotNull);
      expect(left, contains('VPN & Device Management'));
    });
  });

  group('on iOS nothing says Android', () {
    // Every failure message named Android unconditionally, so an iPhone whose
    // tunnel would not come up was told to inspect an Android artifact with a
    // tool that does not exist on the device. The controller is one class for
    // both platforms on purpose; only the wording is per-platform.
    test('a refused approval is about a VPN configuration', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = false
        ..answers['requestPermission'] = false;
      final SingboxTunnel tunnel =
          tunnelFor(platform, text: TunnelPlatformText.ios);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await attempt.settled;

      expect(attempt.message, startsWith('iOS did not approve'));
      expect(attempt.message, isNot(contains('Android')));
      expect(attempt.message, contains('VPN & Device Management'));
    });

    testWidgets('a timeout points at the extension and at os_log',
        (WidgetTester tester) async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel =
          tunnelFor(platform, text: TunnelPlatformText.ios);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await tester.pump(const Duration(seconds: 46));
      await attempt.settled;

      expect(attempt.message, contains('packet-tunnel extension'));
      expect(attempt.message, contains('log stream'));
      expect(attempt.message, isNot(contains('Android')));
      expect(attempt.message, isNot(contains('adb')));
    });

    test('an unregistered channel does not blame Android', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] =
            MissingPluginException('No implementation found');
      final SingboxTunnel tunnel =
          tunnelFor(platform, text: TunnelPlatformText.ios);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await attempt.settled;

      expect(attempt.message, contains('this is not iOS'));
      expect(attempt.message, isNot(contains('Android')));
    });

    test('a broken status feed names iOS', () async {
      final _FakePlatform platform = _FakePlatform()
        ..answers['prepare'] = true
        ..answers['start'] = null;
      final SingboxTunnel tunnel =
          tunnelFor(platform, text: TunnelPlatformText.ios);
      final _Attempt attempt = _Attempt(tunnel.connect(profile));

      await pumpEventQueue();
      platform.breakFeed(code: 'gone', message: 'the extension exited');
      await pumpEventQueue();
      await attempt.settled;

      expect(tunnel.status.message, contains('The iOS status channel failed'));
      expect(tunnel.status.message, isNot(contains('Android')));
    });

    test('a platform this package registers nothing on says which', () {
      final TunnelPlatformText text =
          TunnelPlatformText.forPlatform(TargetPlatform.macOS);

      expect(text.osName, 'macOS');
      expect(text.unregistered, contains('macOS'));
      expect(text.unregistered, isNot(contains('this is not')));
    });
  });
}

/// The platform side of both channels, answered from Dart.
///
/// [answers] maps a method name to what the platform returns for it; an
/// [Exception] there is thrown instead, which is how a `PlatformException` and a
/// `MissingPluginException` are staged. An unanswered method returns null, which
/// is what `start` and `stop` really return.
class _FakePlatform {
  _FakePlatform() {
    final TestDefaultBinaryMessenger messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    // Registered before any SingboxTunnel is built: the constructor subscribes
    // to the status channel immediately, and an EventChannel with no handler
    // fails that subscription, which the controller correctly reports as a
    // broken feed.
    messenger.setMockStreamHandler(
      const EventChannel(statusChannelName),
      // A block body, not an arrow: MockStreamHandler.inline's callback is
      // typed void, and flutter_test encodes whatever it evaluates to as the
      // reply to `listen`. An arrow here returns the sink, which the standard
      // codec cannot encode, and the subscription fails with that instead of
      // succeeding.
      MockStreamHandler.inline(
        onListen: (Object? arguments, MockStreamHandlerEventSink events) {
          _events = events;
        },
      ),
    );
    messenger.setMockMethodCallHandler(
      const MethodChannel(commandChannelName),
      _handle,
    );
  }

  final List<MethodCall> calls = <MethodCall>[];
  final Map<String, Object?> answers = <String, Object?>{};

  MockStreamHandlerEventSink? _events;

  List<String> get methods =>
      calls.map((MethodCall call) => call.method).toList();

  /// Sends one status event, as the platform's own `EventSink` would.
  void emit(Object? event) => _events!.success(event);

  /// Breaks the status feed itself, which is not the same as reporting a failed
  /// tunnel: after this the controller knows nothing about the tunnel's state.
  void breakFeed({required String code, String? message}) =>
      _events!.error(code: code, message: message);

  Future<Object?>? _handle(MethodCall call) async {
    calls.add(call);
    final Object? answer = answers[call.method];
    if (answer is Exception) {
      throw answer;
    }
    return answer;
  }
}

/// One `connect`/`disconnect` call whose outcome can be inspected without
/// awaiting it, because "has it settled yet" is half of what these tests assert.
///
/// It attaches its own error handler at construction, so a failure this test
/// expects never surfaces as an unhandled asynchronous error.
class _Attempt {
  _Attempt(Future<void> call) {
    settled = call.then<void>((void _) {}, onError: (Object error) {
      thrown = error;
    }).whenComplete(() {
      done = true;
    });
  }

  late final Future<void> settled;
  bool done = false;
  Object? thrown;

  /// The failure text, which is what a person is shown. Reading it through
  /// [StateError] is deliberate: `connect` promises to throw with the same
  /// string it emitted.
  String get message => (thrown! as StateError).message;
}

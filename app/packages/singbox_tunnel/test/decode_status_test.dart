// The decoder that turns a platform event into this app's claim about whether
// traffic is being routed.
//
// It is the narrowest place the worst failure this client can have could come
// from: reporting "Connected" when no tunnel exists. Somebody believes it,
// routes their traffic through nothing, and finds out later. So every shape the
// decoder cannot read has to come out as `failed`, and that is asserted here one
// shape at a time -- a wrong type, a missing key, a stage string from a build
// that disagrees with this one -- rather than inferred from the switch reading
// as though it covers them.
//
// `decodeStatus` was deliberately factored out of the controller so it could be
// tested without a channel, and for a while nothing tested it at all.

import 'package:flutter_test/flutter_test.dart';
import 'package:singbox_tunnel/src/channels.dart';
import 'package:singbox_tunnel/src/platform_text.dart';
import 'package:singbox_tunnel/src/singbox_tunnel.dart';
import 'package:singbox_tunnel/tunnel_api.dart';

void main() {
  const String profileId = 'srv-7';

  TunnelStatus decode(
    Object? event, {
    TunnelPlatformText platform = TunnelPlatformText.android,
  }) =>
      decodeStatus(event, profileId, platform);

  group('the four stages the channel contract defines', () {
    test('disconnected', () {
      final TunnelStatus status =
          decode(<Object?, Object?>{'stage': stageDisconnected});

      expect(status.stage, TunnelStage.disconnected);
      expect(status.profileId, profileId);
      expect(status.message, isNull);
    });

    test('connecting', () {
      final TunnelStatus status = decode(<Object?, Object?>{
        'stage': stageConnecting,
        'message': 'Starting sing-box',
      });

      expect(status.stage, TunnelStage.connecting);
      expect(status.message, 'Starting sing-box');
    });

    test('connected', () {
      final TunnelStatus status =
          decode(<Object?, Object?>{'stage': stageConnected});

      expect(status.stage, TunnelStage.connected);
      expect(status.profileId, profileId);
    });

    test('failed keeps the platform text verbatim', () {
      // The failure text is the whole diagnosis -- TunnelStatus.message says it
      // is shown as it stands -- so a summary here would throw away the only
      // thing that says what broke.
      const String detail =
          'libbox refused the configuration: json: cannot unmarshal number '
          'into Go struct field _Options.inbounds of type string';
      final TunnelStatus status = decode(<Object?, Object?>{
        'stage': stageFailed,
        'message': detail,
      });

      expect(status.stage, TunnelStage.failed);
      expect(status.message, detail);
    });
  });

  group('shapes that must never read as connected', () {
    test('an unknown stage is a failure naming the skew', () {
      // A stage string this build does not know means the Dart and the platform
      // code disagree about the contract, which happens when one half of a
      // release lands without the other. Guessing which state the tunnel is in
      // is exactly the guess that would eventually guess "up".
      final TunnelStatus status =
          decode(<Object?, Object?>{'stage': 'reconnecting'});

      expect(status.stage, TunnelStage.failed);
      expect(status.message, contains('"reconnecting"'));
      expect(status.message, contains('Kotlin'));
    });

    test('a stage of the wrong type is a failure, not a match', () {
      final TunnelStatus status = decode(<Object?, Object?>{'stage': 2});

      expect(status.stage, TunnelStage.failed);
      expect(status.message, contains('"2"'));
    });

    test('a map with no stage at all is a failure', () {
      final TunnelStatus status =
          decode(<Object?, Object?>{'message': 'something happened'});

      expect(status.stage, TunnelStage.failed);
      expect(status.message, contains('Unknown tunnel stage "null"'));
    });

    test('an event that is not a map is a failure carrying what arrived', () {
      for (final Object? event in <Object?>[
        null,
        'connected',
        <Object?>[stageConnected],
        42,
      ]) {
        final TunnelStatus status = decode(event);

        expect(status.stage, TunnelStage.failed,
            reason: 'decoded $event as ${status.stage.name}');
        expect(status.message, contains('$event'));
        expect(status.profileId, profileId);
      }
    });
  });

  group('the message field', () {
    test('an empty message is absent, not empty text', () {
      // The platform sends `""` where it has nothing to add, and a UI that
      // renders `message` would otherwise draw an empty line under the state.
      final TunnelStatus status = decode(<Object?, Object?>{
        'stage': stageConnected,
        'message': '',
      });

      expect(status.message, isNull);
    });

    test('a non-string message is ignored rather than stringified', () {
      final TunnelStatus status = decode(<Object?, Object?>{
        'stage': stageConnecting,
        'message': 17,
      });

      expect(status.stage, TunnelStage.connecting);
      expect(status.message, isNull);
    });

    test('a failure with no message names the class that owes one', () {
      // A `failed` event with nothing to show is a bug on the platform side,
      // and the substitute text has to say so: a person reading "failed" with
      // no reason cannot tell a missing message from a missing tunnel.
      final TunnelStatus status =
          decode(<Object?, Object?>{'stage': stageFailed});

      expect(status.message, contains('SingboxVpnService'));
    });
  });

  group('no message names the wrong operating system', () {
    // Every one of these strings named Android unconditionally, so an iPhone
    // was told to go and read `adb logcat` for a service that had never run on
    // it. Each assertion below is on the iOS wording AND on the absence of the
    // other platform's name, because a message that merely mentions iOS while
    // still saying "the Android side" is no better.
    TunnelStatus onIos(Object? event) =>
        decode(event, platform: TunnelPlatformText.ios);

    test('an unreadable event', () {
      final TunnelStatus status = onIos('nonsense');

      expect(status.message, contains('iOS'));
      expect(status.message, isNot(contains('Android')));
    });

    test('an unknown stage names Swift, not Kotlin', () {
      final TunnelStatus status = onIos(<Object?, Object?>{'stage': 'idle'});

      expect(status.message, contains('Swift'));
      expect(status.message, isNot(contains('Kotlin')));
      expect(status.message, isNot(contains('Android')));
    });

    test('a failure with no message names the extension', () {
      final TunnelStatus status = onIos(<Object?, Object?>{'stage': stageFailed});

      expect(status.message, contains('PacketTunnelProvider'));
      expect(status.message, isNot(contains('SingboxVpnService')));
      expect(status.message, isNot(contains('Android')));
    });
  });
}

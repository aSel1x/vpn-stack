// vless:// -> a sing-box outbound, against the URI vless_reality.py builds.
//
// The refusal tests are the ones that matter. A missing `pbk` used to be a
// null three layers down; here it has to be a sentence naming the parameter,
// because the person reading it is holding a phone and has no server.

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/config/config.dart';

import 'config_fakes.dart';

Matcher refusalSaying(Object matcher) =>
    throwsA(isA<ShareUriException>().having(
        (ShareUriException e) => e.reason, 'reason', matcher));

void main() {
  group('a link the server really issued', () {
    test('round-trips every parameter share() emits', () {
      final VlessRealityOutbound out = parseVlessRealityUri(vlessUri());
      expect(out.type, 'vless');
      expect(out.tag, defaultOutboundTag);
      expect(out.server, serverHost);
      expect(out.serverPort, vlessPort);
      expect(out.uuid, vlessUuid);
      expect(out.flow, 'xtls-rprx-vision');
      expect(out.serverName, vlessSni);
      expect(out.fingerprint, 'chrome');
      expect(out.publicKey, realityPublicKey);
      expect(out.shortId, realityShortId);
      expect(out.profileName, 'asel1x');
    });

    test('emits the sing-box 1.14 outbound and nothing else', () {
      expect(parseVlessRealityUri(vlessUri()).toJson(), <String, Object?>{
        'type': 'vless',
        'tag': 'proxy',
        'server': serverHost,
        'server_port': vlessPort,
        'uuid': vlessUuid,
        'flow': 'xtls-rprx-vision',
        'tls': <String, Object?>{
          'enabled': true,
          'server_name': vlessSni,
          'utls': <String, Object?>{'enabled': true, 'fingerprint': 'chrome'},
          'reality': <String, Object?>{
            'enabled': true,
            'public_key': realityPublicKey,
            'short_id': realityShortId,
          },
        },
      });
    });

    test('the tag is the caller\'s, not the profile name', () {
      // The fragment can hold a space or a `#`; route.final references the
      // tag, so a label used as a tag is a config that does not resolve.
      final VlessRealityOutbound out =
          parseVlessRealityUri(vlessUri(fragment: 'kate%27s%20phone'),
              tag: 'server-1');
      expect(out.tag, 'server-1');
      expect(out.toJson()['tag'], 'server-1');
      expect(out.profileName, "kate's phone");
      expect(out.toJson().containsKey('name'), isFalse);
    });

    test('a percent-encoded fragment is decoded exactly once', () {
      // quote() in share() escapes the name; a literal `%20` left in a list
      // row is what a double-decode or a no-decode both look like.
      expect(parseVlessRealityUri(vlessUri(fragment: 'p%C3%A4ivi')).profileName,
          'päivi');
      expect(parseVlessRealityUri(vlessUri(fragment: 'a%2520b')).profileName,
          'a%20b');
    });

    test('no fragment at all is a null name, not an empty one', () {
      expect(parseVlessRealityUri(vlessUri(fragment: null)).profileName, isNull);
      expect(parseVlessRealityUri(vlessUri(fragment: '')).profileName, isNull);
    });

    test('headerType is optional, because sing-box has no key for it', () {
      expect(
          parseVlessRealityUri(vlessUri(change: <String, String?>{
            'headerType': null,
          })).flow,
          'xtls-rprx-vision');
    });
  });

  group('a missing parameter is refused by name', () {
    for (final String key in <String>[
      'encryption',
      'flow',
      'security',
      'sni',
      'fp',
      'pbk',
      'sid',
      'type',
    ]) {
      test('no $key', () {
        expect(
          () => parseVlessRealityUri(
              vlessUri(change: <String, String?>{key: null})),
          refusalSaying(contains('no $key parameter')),
        );
      });
    }

    test('the pbk refusal says what REALITY needs it for', () {
      expect(
        () =>
            parseVlessRealityUri(vlessUri(change: <String, String?>{'pbk': null})),
        refusalSaying(contains('which REALITY cannot connect without')),
      );
    });

    test('an empty value counts as missing', () {
      expect(
        () => parseVlessRealityUri(vlessUri(change: <String, String?>{'sid': ''})),
        refusalSaying(contains('no sid parameter')),
      );
    });
  });

  group('a value this app cannot honour is refused, not approximated', () {
    test('security=tls is not REALITY', () {
      expect(
        () => parseVlessRealityUri(
            vlessUri(change: <String, String?>{'security': 'tls'})),
        refusalSaying(allOf(contains('security is `tls`'), contains('reality'))),
      );
    });

    test('type=ws needs a transport object this builder does not write', () {
      expect(
        () =>
            parseVlessRealityUri(vlessUri(change: <String, String?>{'type': 'ws'})),
        refusalSaying(contains('type is `ws`')),
      );
    });

    test('a flow sing-box does not implement', () {
      expect(
        () => parseVlessRealityUri(
            vlessUri(change: <String, String?>{'flow': 'xtls-rprx-direct'})),
        refusalSaying(contains('flow is `xtls-rprx-direct`')),
      );
    });

    test('an unknown uTLS fingerprint, listing the ones there are', () {
      expect(
        () => parseVlessRealityUri(
            vlessUri(change: <String, String?>{'fp': 'netscape'})),
        refusalSaying(
            allOf(contains('fp is `netscape`'), contains('chrome'))),
      );
    });

    test('headerType=http, which sing-box does not implement', () {
      expect(
        () => parseVlessRealityUri(
            vlessUri(change: <String, String?>{'headerType': 'http'})),
        refusalSaying(contains('headerType is `http`')),
      );
    });
  });

  group('a key that arrived mangled is caught here, not at the handshake', () {
    test('a pbk of the wrong length', () {
      expect(
        () => parseVlessRealityUri(
            vlessUri(change: <String, String?>{'pbk': 'tooshort'})),
        refusalSaying(allOf(contains('pbk is 8 characters'), contains('43'))),
      );
    });

    test('a pbk that is not base64url -- the `+`-as-space bug', () {
      // Uri.queryParameters would turn a `+` into a space and hand sing-box a
      // key of the right length that is not the server's.
      expect(
        () => parseVlessRealityUri(vlessUri(change: <String, String?>{
          'pbk': 'jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI+T4E7RoLJS0',
        })),
        refusalSaying(contains('not unpadded base64url')),
      );
    });

    test('a sid that is not hex', () {
      expect(
        () => parseVlessRealityUri(
            vlessUri(change: <String, String?>{'sid': 'zzzzzzzz'})),
        refusalSaying(contains('not hexadecimal')),
      );
    });

    test('a sid longer than eight bytes', () {
      expect(
        () => parseVlessRealityUri(vlessUri(change: <String, String?>{
          'sid': '0123456789abcdef00',
        })),
        refusalSaying(contains('at most 16')),
      );
    });
  });

  group('a link this server did not produce', () {
    test('an unknown parameter is named, not ignored', () {
      // Same stance as rejectUnknown in control/json.dart: the parameter
      // nobody here reads may be the one that changed the credential's shape.
      expect(
        () => parseVlessRealityUri(
            vlessUri(change: <String, String?>{'allowInsecure': '1'})),
        refusalSaying(contains('allowInsecure')),
      );
    });

    test('a duplicated parameter, rather than last-one-wins', () {
      final String doubled =
          vlessUri().replaceFirst('#asel1x', '&sid=00#asel1x');
      expect(() => parseVlessRealityUri(doubled),
          refusalSaying(contains('`sid` appears more than once')));
    });

    test('a hysteria2 link handed to the vless parser', () {
      expect(() => parseVlessRealityUri(hysteria2Uri()),
          refusalSaying(contains('not a vless URI')));
    });

    test('no port, which share() always writes', () {
      expect(
        () => parseVlessRealityUri(
            'vless://$vlessUuid@$serverHost?encryption=none#x'),
        refusalSaying(contains('no port')),
      );
    });

    test('no credential before the @', () {
      expect(() => parseVlessRealityUri('vless://$serverHost:10443?x=1'),
          refusalSaying(contains('no credential')));
    });
  });

  group('messages are safe to log', () {
    // The credential is in the userinfo and the obfs password is in the query,
    // so a refusal that echoed the URI would put a live credential into a log
    // or a crash report. Same stance as UserSecrets being its own type in the
    // control layer.
    test('no refusal echoes the uuid or the key', () {
      final List<String> broken = <String>[
        vlessUri(change: <String, String?>{'pbk': null}),
        vlessUri(change: <String, String?>{'security': 'tls'}),
        vlessUri(change: <String, String?>{'allowInsecure': '1'}),
      ];
      for (int i = 0; i < broken.length; i++) {
        try {
          parseVlessRealityUri(broken[i]);
          fail('link $i was accepted and should not have been');
        } on ShareUriException catch (e) {
          expect(e.message, isNot(contains(vlessUuid)));
          expect(e.message, isNot(contains(realityPublicKey)));
          expect(e.where, 'vless://…@$serverHost:$vlessPort');
        }
      }
    });
  });
}

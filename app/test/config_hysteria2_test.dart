// hysteria2:// -> a sing-box outbound, against the URI hysteria2.py builds.
//
// The interesting half of this file is `pinSHA256`. The server pins its
// self-signed certificate by SHA-256 of the DER certificate; sing-box 1.14's
// only fingerprint key is `certificate_public_key_sha256`, which hashes the
// SubjectPublicKeyInfo and encodes it as base64 -- a different preimage and a
// different encoding. So the pin is parsed, kept, and NOT emitted, and the
// caller has to say what to trust instead.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/config/config.dart';

import 'config_fakes.dart';

Matcher refusalSaying(Object matcher) =>
    throwsA(isA<ShareUriException>().having(
        (ShareUriException e) => e.reason, 'reason', matcher));

void main() {
  _regressions();

  // The link the server really issued, against the transcription every other
  // test in this file works from.
  //
  // `hysteria2ShareParams` is a hand copy of the f-string in hysteria2.py's
  // share(), and `spki` is in it because it once was not: it was added to
  // share() and nothing here noticed, so every test passed while the parser
  // refused every real link for carrying a parameter it did not know. The URI
  // below comes out of test/fixtures/user-export.json, which
  // tests/test_json_contract.py generates by calling share() and then holds
  // cli.py to -- so the next parameter cannot arrive unannounced.
  group('the generated link, against the transcription', () {
    final String generated = fixtureShareUri('hysteria2');

    test('carries exactly the parameters this file transcribes, in order', () {
      expect(
        shareUriQuery(generated).map((List<String> p) => p[0]).toList(),
        hysteria2ShareParams.map((List<String> p) => p[0]).toList(),
      );
    });

    test('emits both pins, which are not convertible into one another', () {
      // pinSHA256 hashes the whole DER certificate; spki hashes the
      // SubjectPublicKeyInfo and base64s it. Different preimage, different
      // encoding, and sing-box can only check the second -- which is why
      // share() emits both and dropping either one costs a whole class of
      // client its ability to connect. Asserted on the generated link because
      // that is the only place the two can be seen to be different values.
      final Map<String, String> params = <String, String>{
        for (final List<String> pair in shareUriQuery(generated))
          pair[0]: pair[1],
      };
      expect(params['pinSHA256'], isNotNull);
      expect(params['spki'], isNotNull);
      expect(params['spki'], isNot(params['pinSHA256']));
      expect(params['obfs'], 'salamander');
      expect(params['sni'], hysteria2Sni);
    });

    test('the spki pin survives the query decoding, `+` and all', () {
      // The reason share_uri.dart refuses to use `Uri.queryParameters`: form
      // decoding turns `+` into a space. The fixture's certificate is chosen so
      // its SPKI hash base64s with both a `+` and a `/` in it -- the `+`
      // arrives percent-encoded, the `/` literal -- so a parser that decoded
      // with the form rules would hand sing-box a pin that is not the one the
      // server published, and the handshake would fail with a TLS error that
      // says nothing about a pin.
      expect(generated, contains('%2B'));
      final Hysteria2Outbound out = parseHysteria2Uri(generated,
          trust: Hysteria2Trust.systemRoots);
      expect(out.spkiSha256, contains('+'));
      expect(out.spkiSha256, contains('/'));
      expect(out.spkiSha256, endsWith('='));
      // 32 bytes, base64: SHA-256 of the SubjectPublicKeyInfo and nothing else.
      expect(base64Decode(out.spkiSha256!).length, 32);
      expect(out.serverName, hysteria2Sni);
      expect(out.profileName, 'kate');
      expect(out.serverPort, hysteria2Port);
    });
  });

  group('a link the server really issued', () {
    test('round-trips every parameter share() emits', () {
      final Hysteria2Outbound out = parseHysteria2Uri(hysteria2Uri(),
          trust: Hysteria2Trust.systemRoots);
      expect(out.type, 'hysteria2');
      expect(out.tag, defaultOutboundTag);
      expect(out.server, serverHost);
      expect(out.serverPort, hysteria2Port);
      expect(out.password, hysteria2Password);
      expect(out.obfsType, 'salamander');
      expect(out.obfsPassword, obfsPassword);
      expect(out.serverName, hysteria2Sni);
      expect(out.pinSha256, certificatePin);
      expect(out.profileName, 'asel1x');
    });

    test('a percent-encoded fragment is the profile name', () {
      expect(
          parseHysteria2Uri(hysteria2Uri(fragment: 'kate%27s%20phone'),
                  trust: Hysteria2Trust.systemRoots)
              .profileName,
          "kate's phone");
    });

    test('up_mbps and down_mbps are absent: the link carries no bandwidth', () {
      // Declaring numbers here switches the client from BBR to Hysteria's
      // Brutal congestion control on evidence that is not in the link.
      final Map<String, Object?> json = parseHysteria2Uri(hysteria2Uri(),
              trust: Hysteria2Trust.systemRoots)
          .toJson();
      expect(json.containsKey('up_mbps'), isFalse);
      expect(json.containsKey('down_mbps'), isFalse);
    });
  });

  group('the optional parameters', () {
    test('no obfs at all: no obfs object in the outbound', () {
      final Hysteria2Outbound out = parseHysteria2Uri(
        hysteria2Uri(change: <String, String?>{
          'obfs': null,
          'obfs-password': null,
        }),
        trust: Hysteria2Trust.systemRoots,
      );
      expect(out.obfsType, isNull);
      expect(out.obfsPassword, isNull);
      expect(out.toJson().containsKey('obfs'), isFalse);
    });

    test('no pinSHA256: nothing was pinned, so nothing is unenforced', () {
      final Hysteria2Outbound out = parseHysteria2Uri(
        hysteria2Uri(change: <String, String?>{'pinSHA256': null}),
        trust: Hysteria2Trust.systemRoots,
      );
      expect(out.pinSha256, isNull);
      expect(out.pinUnenforced, isFalse);
    });

    test('obfs without its password is refused, not silently disabled', () {
      // Salamander with no password is not "obfuscation off": sing-box builds
      // the obfuscator anyway and the server never sees a handshake.
      expect(
        () => parseHysteria2Uri(
          hysteria2Uri(change: <String, String?>{'obfs-password': null}),
          trust: Hysteria2Trust.systemRoots,
        ),
        refusalSaying(contains('obfs is set but obfs-password is not')),
      );
    });

    test('a password with no obfs to use it', () {
      expect(
        () => parseHysteria2Uri(
          hysteria2Uri(change: <String, String?>{'obfs': null}),
          trust: Hysteria2Trust.systemRoots,
        ),
        refusalSaying(contains('obfs-password is set but obfs is not')),
      );
    });
  });

  group('the pin sing-box has no field for, on a link that predates spki', () {
    // These describe a link issued before share() emitted `spki`: pinSHA256
    // alone, which sing-box has no field for. Every profile already handed out
    // looks like this, which is why the parser still accepts it.
    String legacy() => hysteria2Uri(change: <String, String?>{'spki': null});

    test('the certificate pin is kept on the model and never emitted', () {
      final Hysteria2Outbound out =
          parseHysteria2Uri(legacy(), trust: Hysteria2Trust.systemRoots);
      expect(out.pinUnenforced, isTrue);
      final Map<String, Object?> tls =
          out.toJson()['tls']! as Map<String, Object?>;
      expect(tls.containsKey('certificate_public_key_sha256'), isFalse);
      expect(out.toJson().toString(), isNot(contains(certificatePin)));
    });

    test('systemRoots emits no trust override at all', () {
      final Map<String, Object?> tls =
          parseHysteria2Uri(legacy(), trust: Hysteria2Trust.systemRoots)
              .toJson()['tls']! as Map<String, Object?>;
      expect(tls, <String, Object?>{
        'enabled': true,
        'server_name': hysteria2Sni,
      });
    });

    test('anyCertificate emits tls.insecure, which is the whole downgrade', () {
      final Map<String, Object?> tls =
          parseHysteria2Uri(legacy(), trust: Hysteria2Trust.anyCertificate)
              .toJson()['tls']! as Map<String, Object?>;
      expect(tls, <String, Object?>{
        'enabled': true,
        'server_name': hysteria2Sni,
        'insecure': true,
      });
    });

    test('a current link needs none of this', () {
      // The contrast is the point: with spki the same URI is verified, and the
      // trust argument stops mattering.
      final Map<String, Object?> tls =
          parseHysteria2Uri(hysteria2Uri(), trust: Hysteria2Trust.anyCertificate)
              .toJson()['tls']! as Map<String, Object?>;
      expect(tls['certificate_public_key_sha256'], <String>[certificateSpki]);
      expect(tls.containsKey('insecure'), isFalse);
    });
  });

  group('a link this server did not produce', () {
    test('no sni, which the certificate is issued for', () {
      expect(
        () => parseHysteria2Uri(
          hysteria2Uri(change: <String, String?>{'sni': null}),
          trust: Hysteria2Trust.systemRoots,
        ),
        refusalSaying(contains('no sni parameter')),
      );
    });

    test('an obfuscator this server does not issue', () {
      expect(
        () => parseHysteria2Uri(
          hysteria2Uri(change: <String, String?>{'obfs': 'gecko'}),
          trust: Hysteria2Trust.systemRoots,
        ),
        refusalSaying(contains('obfs is `gecko`')),
      );
    });

    test('insecure=1, which other panels emit and this one does not', () {
      expect(
        () => parseHysteria2Uri(
          hysteria2Uri(change: <String, String?>{'insecure': '1'}),
          trust: Hysteria2Trust.systemRoots,
        ),
        refusalSaying(contains('insecure')),
      );
    });

    test('a vless link handed to the hysteria2 parser', () {
      expect(
        () =>
            parseHysteria2Uri(vlessUri(), trust: Hysteria2Trust.systemRoots),
        refusalSaying(contains('not a hysteria2 URI')),
      );
    });
  });

  group('messages are safe to log', () {
    test('no refusal echoes the password or the obfs key', () {
      try {
        parseHysteria2Uri(
          hysteria2Uri(change: <String, String?>{'sni': null}),
          trust: Hysteria2Trust.systemRoots,
        );
        fail('a link with no sni was accepted');
      } on ShareUriException catch (e) {
        expect(e.message, isNot(contains(hysteria2Password)));
        expect(e.message, isNot(contains(obfsPassword)));
        expect(e.where, 'hysteria2://…@$serverHost:$hysteria2Port');
      }
    });
  });
}

void _regressions() {
  group('the quadrants the first pass missed', () {
    test('a link with no pin, trusted as anyCertificate, says so out loud', () {
      // The dangerous combination: tls.insecure is emitted and pinUnenforced is
      // false, because there was no pin to be unenforced. Nothing warned.
      final Hysteria2Outbound out = parseHysteria2Uri(
        'hysteria2://pw@203.0.113.10:20443?sni=www.bing.com#kate',
        trust: Hysteria2Trust.anyCertificate,
      );
      expect(out.pinSha256, isNull);
      expect(out.pinUnenforced, isFalse);
      expect(out.acceptsAnyCertificate, isTrue,
          reason: 'the config accepts any certificate; a UI must be able to say so');
      final Map<String, Object?> tls =
          out.toJson()['tls']! as Map<String, Object?>;
      expect(tls['insecure'], isTrue);
    });

    test('a bare IPv6 authority is refused, not split inside the address', () {
      // lastIndexOf(':') turned 2001:db8::1 into host `2001:db8:` on port 1 --
      // a config that parses and can never connect.
      expect(
        () => parseHysteria2Uri(
          'hysteria2://pw@2001:db8::1?sni=www.bing.com',
          trust: Hysteria2Trust.systemRoots,
        ),
        throwsA(isA<ShareUriException>()),
      );
    });

    test('a link carrying spki pins the public key and needs no trust decision',
        () {
      // The whole point of the server-side change: with a pin sing-box can
      // check, there is no choice between failing the handshake and trusting
      // anything. Both trust values must produce the same, verified config.
      const String spki = 'BzXhPQ2yVCkGDXK5dRJiTlIz3bMUwEZAfTZP1xhbQ0E=';
      for (final Hysteria2Trust trust in Hysteria2Trust.values) {
        final Hysteria2Outbound out = parseHysteria2Uri(
          'hysteria2://pw@203.0.113.10:20443?sni=www.bing.com&spki=$spki#kate',
          trust: trust,
        );
        expect(out.spkiSha256, spki);
        expect(out.acceptsAnyCertificate, isFalse,
            reason: 'a pinned key is checked, whatever the trust setting says');
        final Map<String, Object?> tls =
            out.toJson()['tls']! as Map<String, Object?>;
        expect(tls['certificate_public_key_sha256'], <String>[spki]);
        expect(tls.containsKey('insecure'), isFalse,
            reason: 'insecure is what you emit when you cannot verify; here we can');
      }
    });

    test('a link from before the server emitted spki still parses', () {
      // Every profile already handed out lacks it. Refusing those would strand
      // them, so it is optional and the old trust decision still applies.
      final Hysteria2Outbound out = parseHysteria2Uri(
        'hysteria2://pw@203.0.113.10:20443?sni=www.bing.com&pinSHA256=AA:BB#kate',
        trust: Hysteria2Trust.anyCertificate,
      );
      expect(out.spkiSha256, isNull);
      expect(out.acceptsAnyCertificate, isTrue);
    });

    test('a bracketed IPv6 authority still works', () {
      final Hysteria2Outbound out = parseHysteria2Uri(
        'hysteria2://pw@[2001:db8::1]:20443?sni=www.bing.com',
        trust: Hysteria2Trust.systemRoots,
      );
      expect(out.server, '2001:db8::1');
      expect(out.serverPort, 20443);
    });
  });
}

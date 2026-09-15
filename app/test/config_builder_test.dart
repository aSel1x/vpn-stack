// The whole configuration, assembled.
//
// The golden here is the deliverable. Nothing in this repository can run
// sing-box, so the only thing standing between a renamed key and a tunnel that
// will not come up on somebody's phone is a test that states, in full, what is
// emitted. A change to any of it shows up as a diff a person reads.
//
// Two goldens, deliberately. The map is what is emitted; the sorted key paths
// are the KEY SET, and that is the thing to check against sing-box's
// documentation when the pinned version in compose.yml moves -- sing-box
// refuses a whole config over one key it does not know.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:vpn_stack_app/config/config.dart';

import 'config_fakes.dart';

/// Every leaf in [node], as a dotted path, sorted.
List<String> keyPaths(Map<String, Object?> node, [String prefix = '']) {
  final List<String> out = <String>[];
  node.forEach((String key, Object? value) {
    final String path = prefix.isEmpty ? key : '$prefix.$key';
    if (value is Map<String, Object?>) {
      out.addAll(keyPaths(value, path));
    } else if (value is List<Object?>) {
      for (int i = 0; i < value.length; i++) {
        final Object? item = value[i];
        if (item is Map<String, Object?>) {
          out.addAll(keyPaths(item, '$path[$i]'));
        } else {
          out.add('$path[$i]');
        }
      }
    } else {
      out.add(path);
    }
  });
  out.sort();
  return out;
}

void main() {
  group('the full configuration for a VLESS+REALITY link', () {
    test('is exactly this', () {
      final Map<String, Object?> config = buildSingBoxConfig(
        outbound: parseVlessRealityUri(vlessUri()),
      );
      expect(config, <String, Object?>{
        'log': <String, Object?>{'level': 'info', 'timestamp': true},
        'dns': <String, Object?>{
          'servers': <Map<String, Object?>>[
            <String, Object?>{
              'type': 'udp',
              'tag': 'dns-remote',
              'server': '1.1.1.1',
              'detour': 'proxy',
            },
            <String, Object?>{'type': 'local', 'tag': 'dns-local'},
          ],
          'final': 'dns-remote',
          'strategy': 'prefer_ipv4',
        },
        'inbounds': <Map<String, Object?>>[
          <String, Object?>{
            'type': 'tun',
            'tag': 'tun-in',
            'address': <String>['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
            'mtu': 9000,
            'auto_route': true,
            'strict_route': false,
            'stack': 'mixed',
          },
        ],
        'outbounds': <Map<String, Object?>>[
          <String, Object?>{
            'type': 'vless',
            'tag': 'proxy',
            'server': serverHost,
            'server_port': vlessPort,
            'uuid': vlessUuid,
            'flow': 'xtls-rprx-vision',
            'tls': <String, Object?>{
              'enabled': true,
              'server_name': vlessSni,
              'utls': <String, Object?>{
                'enabled': true,
                'fingerprint': 'chrome',
              },
              'reality': <String, Object?>{
                'enabled': true,
                'public_key': realityPublicKey,
                'short_id': realityShortId,
              },
            },
          },
        ],
        'route': <String, Object?>{
          'rules': <Map<String, Object?>>[
            <String, Object?>{'action': 'sniff'},
            <String, Object?>{'protocol': 'dns', 'action': 'hijack-dns'},
          ],
          'final': 'proxy',
          'auto_detect_interface': true,
          'default_domain_resolver': 'dns-local',
        },
      });
    });

    test('emits these keys and no others', () {
      // Every path below was checked against sing-box v1.14.0's own docs.
      // Adding one means checking it there first; a key sing-box does not know
      // makes it refuse the whole file at startup, on a device, with nobody
      // to read the message.
      final Map<String, Object?> config =
          buildSingBoxConfig(outbound: parseVlessRealityUri(vlessUri()));
      expect(keyPaths(config), <String>[
            'dns.final',
            'dns.servers[0].detour',
            'dns.servers[0].server',
            'dns.servers[0].tag',
            'dns.servers[0].type',
            'dns.servers[1].tag',
            'dns.servers[1].type',
            'dns.strategy',
            'inbounds[0].address[0]',
            'inbounds[0].address[1]',
            'inbounds[0].auto_route',
            'inbounds[0].mtu',
            'inbounds[0].stack',
            'inbounds[0].strict_route',
            'inbounds[0].tag',
            'inbounds[0].type',
            'log.level',
            'log.timestamp',
            'outbounds[0].flow',
            'outbounds[0].server',
            'outbounds[0].server_port',
            'outbounds[0].tag',
            'outbounds[0].tls.enabled',
            'outbounds[0].tls.reality.enabled',
            'outbounds[0].tls.reality.public_key',
            'outbounds[0].tls.reality.short_id',
            'outbounds[0].tls.server_name',
            'outbounds[0].tls.utls.enabled',
            'outbounds[0].tls.utls.fingerprint',
            'outbounds[0].type',
            'outbounds[0].uuid',
            'route.auto_detect_interface',
            'route.default_domain_resolver',
            'route.final',
            'route.rules[0].action',
            'route.rules[1].action',
            'route.rules[1].protocol',
          ]);
    });

    test('survives jsonEncode unchanged -- no Map key is not a String', () {
      final Map<String, Object?> config =
          buildSingBoxConfig(outbound: parseVlessRealityUri(vlessUri()));
      final Map<String, Object?> round =
          jsonDecode(encodeSingBoxConfig(config)) as Map<String, Object?>;
      expect(round, config);
    });
  });

  group('the pieces are wired to each other, not to constants', () {
    test('the DNS detour, route.final and the outbound tag are one string', () {
      final Map<String, Object?> config = buildSingBoxConfig(
        outbound: parseVlessRealityUri(vlessUri(), tag: 'stockholm'),
      );
      final Map<String, Object?> dns = config['dns']! as Map<String, Object?>;
      final List<Object?> servers = dns['servers']! as List<Object?>;
      final Map<String, Object?> remote = servers.first! as Map<String, Object?>;
      final Map<String, Object?> route =
          config['route']! as Map<String, Object?>;
      // A tunnel whose DNS detours to a tag nothing defines fails to start,
      // and the message names the tag rather than the mistake.
      expect(remote['detour'], 'stockholm');
      expect(route['final'], 'stockholm');
    });

    test('default_domain_resolver points at the LOCAL resolver', () {
      // Resolving the VPN server's own hostname through the VPN is the loop
      // this key exists to break, and 1.14 requires the key rather than
      // inferring it.
      final Map<String, Object?> route = buildSingBoxConfig(
        outbound: parseVlessRealityUri(vlessUri()),
      )['route']! as Map<String, Object?>;
      expect(route['default_domain_resolver'], 'dns-local');
    });

    test('a platform can hand in its own tun inbound', () {
      // The reason the pieces are separate objects: Android and iOS want a
      // different tun and must not need a different builder.
      final Map<String, Object?> config = buildSingBoxConfig(
        outbound: parseVlessRealityUri(vlessUri()),
        inbound: const TunInbound(
          tag: 'tun-android',
          stack: 'gvisor',
          strictRoute: true,
          mtu: 1500,
        ),
      );
      final List<Object?> inbounds = config['inbounds']! as List<Object?>;
      expect(inbounds.single, <String, Object?>{
        'type': 'tun',
        'tag': 'tun-android',
        'address': <String>['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
        'mtu': 1500,
        'auto_route': true,
        'strict_route': true,
        'stack': 'gvisor',
      });
    });

    test('a Hysteria2 outbound drops straight into the same config', () {
      final Map<String, Object?> config = buildSingBoxConfig(
        outbound: parseHysteria2Uri(hysteria2Uri(),
            trust: Hysteria2Trust.anyCertificate),
      );
      final List<Object?> outbounds = config['outbounds']! as List<Object?>;
      expect(outbounds.single, <String, Object?>{
        'type': 'hysteria2',
        'tag': 'proxy',
        'server': serverHost,
        'server_port': hysteria2Port,
        'password': hysteria2Password,
        'obfs': <String, Object?>{
          'type': 'salamander',
          'password': obfsPassword,
        },
        'tls': <String, Object?>{
          'enabled': true,
          'server_name': hysteria2Sni,
          // The link carries `spki`, so the self-signed certificate is pinned
          // by public key and there is nothing to downgrade. `insecure` is what
          // this said before the server published a hash sing-box can check.
          'certificate_public_key_sha256': <String>[certificateSpki],
        },
      });
      // Everything around the outbound is unchanged: that is the point of the
      // outbound being the only protocol-shaped thing in the file.
      final Map<String, Object?> viaVless =
          buildSingBoxConfig(outbound: parseVlessRealityUri(vlessUri()));
      expect(keyPaths(config['route']! as Map<String, Object?>),
          keyPaths(viaVless['route']! as Map<String, Object?>));
    });
  });

  group('picking a URI out of a share bundle', () {
    test('takes the first importable one, which is registry order', () {
      // ShareBundle.importUris is registry order: VLESS+REALITY (order 10)
      // before Hysteria2 (order 20). REALITY verifies a real handshake; the
      // Hysteria2 certificate here is self-signed and its pin is unenforceable.
      final OutboundConfig out = selectOutbound(
        <String>[vlessUri(), hysteria2Uri()],
        hysteria2Trust: Hysteria2Trust.systemRoots,
      );
      expect(out, isA<VlessRealityOutbound>());
    });

    test('falls through to the next when the first cannot be imported', () {
      final OutboundConfig out = selectOutbound(
        <String>[
          'vmess://something-from-another-panel',
          hysteria2Uri(),
        ],
        hysteria2Trust: Hysteria2Trust.systemRoots,
      );
      expect(out, isA<Hysteria2Outbound>());
    });

    test('an empty bundle says there is nothing to connect with', () {
      expect(
        () => selectOutbound(const <String>[],
            hysteria2Trust: Hysteria2Trust.systemRoots),
        throwsA(isA<ShareUriException>().having(
            (ShareUriException e) => e.reason,
            'reason',
            contains('no importable URI'))),
      );
    });

    test('when none can be imported, every refusal survives', () {
      // One "no usable profile" would hide the line that says which parameter
      // was missing, which is the only line worth reading.
      expect(
        () => selectOutbound(
          <String>[
            vlessUri(change: <String, String?>{'pbk': null}),
            hysteria2Uri(change: <String, String?>{'sni': null}),
          ],
          hysteria2Trust: Hysteria2Trust.systemRoots,
        ),
        throwsA(isA<ShareUriException>().having(
            (ShareUriException e) => e.reason,
            'reason',
            allOf(contains('no pbk parameter'), contains('no sni parameter')))),
      );
    });

    test('a scheme this app does not import is named', () {
      expect(
        () => parseShareUri('trojan://p@$serverHost:443#x',
            hysteria2Trust: Hysteria2Trust.systemRoots),
        throwsA(isA<ShareUriException>().having(
            (ShareUriException e) => e.where, 'where', contains('trojan'))),
      );
    });

    test('a string with no scheme at all does not echo itself', () {
      // It may be a password somebody pasted into the wrong box, and this
      // string ends up in logs.
      expect(
        () => parseShareUri('hunter2',
            hysteria2Trust: Hysteria2Trust.systemRoots),
        throwsA(isA<ShareUriException>().having(
            (ShareUriException e) => e.message,
            'message',
            allOf(contains('no scheme'), isNot(contains('hunter2'))))),
      );
    });
  });
}

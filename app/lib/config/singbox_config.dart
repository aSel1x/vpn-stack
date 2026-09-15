// Assembling a client configuration for sing-box v1.14.0 -- the version
// compose.yml pins the server to (`ghcr.io/sagernet/sing-box:v1.14.0`), read
// from there rather than restated, the same discipline scripts/check.sh uses.
//
// That premise was wrong when it was written and is right now, which is worth
// saying because the gap was real: compose.yml pins the SERVER's image, while
// these keys configure the CLIENT engine. Those were two unrelated binaries
// until the `libbox` job in .github/workflows/app.yml started building the
// client library from the same line of compose.yml. Now one number governs
// both ends. Break that link and this file silently targets a binary nobody
// constrains -- and the window is narrow: `dns.servers[].type: local` and
// `route.default_domain_resolver` need >= 1.12, `action: sniff` needs >= 1.11,
// and `tun.stack` is deprecated in 1.15.
//
// Still unchecked anywhere: whether sing-box ACCEPTS what this emits. The
// goldens assert the bytes, not the engine's opinion of them -- the gap
// scripts/check.sh closes on the server side and nothing closes here.
//
// Every key here was checked against the v1.14.0 tag's own docs. That is not
// pedantry: sing-box removes keys between minor versions and refuses the whole
// file when it meets one it does not know, so a config written against 1.11
// fails at startup on the device with a message whoever is holding the phone
// cannot act on. Four that were checked and deliberately NOT written:
//
//   * `inbound.sniff` / `inbound.domain_strategy` -- moved to route rule
//     actions in 1.11 and removed from inbounds in 1.12. The `sniff` action
//     below is the replacement.
//   * dial `domain_strategy` -- deprecated in 1.12, REMOVED in 1.14.
//   * `dns.servers[].address` (the URL form) -- replaced in 1.12 by typed
//     servers, which is what `type: udp` / `type: local` below are.
//   * `tun.dns_mode` / `tun.dns_address` -- both NEW in 1.14, and both left
//     out because what they default to was not established. The `hijack-dns`
//     route rule below is the mechanism that has worked since 1.11; if
//     `dns_mode` turns out to default to `hijack`, the rule is redundant and
//     harmless, and if it does not, the rule is what makes DNS work at all.
//     Writing the new keys on an assumption is the bet not worth taking.
//
// The pieces are separate objects on purpose. A platform layer will need its
// own tun inbound -- Android wants package filters and a gvisor stack, iOS
// cannot set `auto_redirect` at all -- and it should get there by passing a
// different [TunInbound], not by editing this file. There is no platform code
// here and there should not be.

import 'dart:convert';

import 'outbound.dart';

/// `log`. Fields: disabled, level, output, timestamp.
class LogOptions {
  const LogOptions({this.level = 'info', this.timestamp = true});

  /// trace, debug, info, warn, error, fatal, panic.
  final String level;

  final bool timestamp;

  /// `output` is not written. It is a file path, and a path that exists on a
  /// desktop does not exist inside an iOS extension's sandbox; whoever owns
  /// the platform layer picks it.
  Map<String, Object?> toJson() => <String, Object?>{
        'level': level,
        'timestamp': timestamp,
      };
}

/// The `tun` inbound.
///
/// Defaults are the cross-platform ones. Anything platform-specific --
/// `auto_redirect` (Linux only), `include_package` (Android only),
/// `stack: gvisor` -- is deliberately absent rather than defaulted, because a
/// key that is only valid on one platform makes the config fail to parse
/// everywhere else.
class TunInbound {
  const TunInbound({
    this.tag = 'tun-in',
    this.address = const <String>['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
    this.mtu = 9000,
    this.autoRoute = true,
    this.strictRoute = false,
    this.stack = 'mixed',
  });

  final String tag;

  /// `address`, since 1.10 -- `inet4_address`/`inet6_address` were removed in
  /// 1.12. 172.19/16 rather than the docs' 172.18: Docker hands out 172.17 and
  /// 172.18 by default, and a tun that overlaps the bridge the user's own
  /// containers sit on is a routing loop on a developer's laptop.
  final List<String> address;

  final int mtu;

  /// Sets the default route to the tun. Needs
  /// `route.auto_detect_interface` (which [buildRoute] writes) or the
  /// outbound's own packets go back into the tun.
  final bool autoRoute;

  /// Off by default, and that is a trade: on it stops DNS leaking past the
  /// tunnel on Windows, and it also makes unsupported networks unreachable on
  /// Linux and needs firewall privileges some platforms will not grant. It is
  /// a platform decision, so the platform layer sets it.
  final bool strictRoute;

  /// system, gvisor, or mixed.
  final String stack;

  Map<String, Object?> toJson() => <String, Object?>{
        'type': 'tun',
        'tag': tag,
        'address': address,
        'mtu': mtu,
        'auto_route': autoRoute,
        'strict_route': strictRoute,
        'stack': stack,
      };
}

/// `dns`, in the typed-server form 1.12 introduced.
class DnsOptions {
  const DnsOptions({
    this.remoteTag = 'dns-remote',
    this.remoteServer = '1.1.1.1',
    this.localTag = 'dns-local',
    this.strategy = 'prefer_ipv4',
  });

  /// Tag of the resolver reached THROUGH the tunnel. Everything the user asks
  /// for is resolved here, so the local network never sees the names.
  final String remoteTag;

  /// An IP literal, never a hostname: a resolver whose own address needs
  /// resolving is the loop this layer exists to avoid.
  final String remoteServer;

  /// Tag of the platform resolver, reached directly. It has exactly one job --
  /// resolving the VPN server's own address, via
  /// `route.default_domain_resolver` -- and it must not go through the tunnel
  /// to do it, because the tunnel is what it is being asked to bring up.
  final String localTag;

  /// prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only.
  final String strategy;

  Map<String, Object?> toJson({required String detour}) => <String, Object?>{
        'servers': <Map<String, Object?>>[
          <String, Object?>{
            'type': 'udp',
            'tag': remoteTag,
            'server': remoteServer,
            'detour': detour,
          },
          <String, Object?>{
            'type': 'local',
            'tag': localTag,
          },
        ],
        'final': remoteTag,
        'strategy': strategy,
      };
}

/// `route`.
Map<String, Object?> buildRoute({
  required String finalOutbound,
  required String domainResolver,
  bool autoDetectInterface = true,
}) =>
    <String, Object?>{
      'rules': <Map<String, Object?>>[
        // Since 1.11 sniffing is a rule action, not an inbound flag. Without
        // it nothing downstream knows a UDP packet on some port is DNS, and
        // the hijack below never fires.
        <String, Object?>{'action': 'sniff'},
        // Whatever resolver the OS points at is an address inside the tun's
        // route; this hands those queries to the `dns` block above instead of
        // forwarding them to a server that is not there.
        <String, Object?>{'protocol': 'dns', 'action': 'hijack-dns'},
      ],
      'final': finalOutbound,
      'auto_detect_interface': autoDetectInterface,
      // Since 1.12. The docs make it optional only while exactly one DNS
      // server is configured; this config has two, so an outbound whose
      // `server` is a hostname has nothing to resolve it with unless this is
      // set. It points at the LOCAL resolver on purpose -- resolving the VPN
      // server's own name through the VPN is the loop.
      'default_domain_resolver': domainResolver,
    };

/// One complete sing-box client configuration, ready for [jsonEncode].
///
/// A Dart map, assembled -- never a template with holes in it. A config built
/// by string concatenation cannot be compared against anything, so the golden
/// test that catches a renamed key could not exist.
Map<String, Object?> buildSingBoxConfig({
  required OutboundConfig outbound,
  TunInbound inbound = const TunInbound(),
  DnsOptions dns = const DnsOptions(),
  LogOptions log = const LogOptions(),
  bool autoDetectInterface = true,
}) =>
    <String, Object?>{
      'log': log.toJson(),
      'dns': dns.toJson(detour: outbound.tag),
      'inbounds': <Map<String, Object?>>[inbound.toJson()],
      'outbounds': <Map<String, Object?>>[outbound.toJson()],
      'route': buildRoute(
        finalOutbound: outbound.tag,
        domainResolver: dns.localTag,
        autoDetectInterface: autoDetectInterface,
      ),
    };

/// The configuration as the bytes an engine is handed.
///
/// Indented, because the only time a person reads one of these is when a
/// tunnel will not come up and they are looking for the key that is wrong.
String encodeSingBoxConfig(Map<String, Object?> config) =>
    const JsonEncoder.withIndent('  ').convert(config);

// vless:// -> [VlessRealityOutbound].
//
// The producer is vpnctl/protocols/vless_reality.py's share(), and nothing
// else is accepted. Every parameter below has a line there that writes it:
//
//   vless://<uuid>@<host>:10443?encryption=none&flow=xtls-rprx-vision
//     &security=reality&sni=<masquerade>&fp=chrome&pbk=<x25519 pub>
//     &sid=<short id>&type=tcp&headerType=none#<name>
//
// Three of those have no sing-box key at all and are validated rather than
// translated: `encryption` (VLESS has no encryption layer of its own),
// `type=tcp` (a sing-box outbound with no `transport` object IS TCP), and
// `headerType=none` (v2ray's TCP header obfuscation, which sing-box does not
// implement). Validating them is not ceremony: a link that says `type=ws`
// needs a `transport` object this builder does not write, and importing it
// while ignoring the difference produces a profile that cannot connect and
// says nothing about why.

import 'outbound.dart';
import 'share_uri.dart';

const String vlessScheme = 'vless';

/// The only `flow` sing-box 1.14 implements, and the only one the server
/// issues -- its inbound writes the same string into every user.
const String _flow = 'xtls-rprx-vision';

/// uTLS fingerprints sing-box 1.14 knows. An unknown one is a parse error on
/// the device, at startup, in a place with no operator.
const Set<String> _fingerprints = <String>{
  'chrome',
  'firefox',
  'edge',
  'safari',
  '360',
  'qq',
  'ios',
  'android',
  'random',
  'randomized',
};

const Set<String> _known = <String>{
  'encryption',
  'flow',
  'security',
  'sni',
  'fp',
  'pbk',
  'sid',
  'type',
  'headerType',
};

/// Parses one `vless://` share link. Pure.
VlessRealityOutbound parseVlessRealityUri(
  String text, {
  String tag = defaultOutboundTag,
}) {
  final ShareUriParts parts = splitShareUri(text, scheme: vlessScheme);
  parts.rejectUnknownParameters(_known);

  // VLESS has no encryption of its own; `none` is the only value the scheme
  // defines and the only one the server writes. sing-box has no key for it.
  parts.requireOneOf(
      'encryption', 'which every VLESS link carries', const <String>{'none'});
  // A sing-box outbound with no `transport` object is plain TCP. There is no
  // `type` or `headerType` key to write either of these into.
  parts.requireOneOf(
      'type', 'which says which transport to build', const <String>{'tcp'});
  final String? headerType = parts.params['headerType'];
  if (headerType != null && headerType != 'none') {
    parts.refuse('headerType is `$headerType`; sing-box does not implement '
        "v2ray's TCP header obfuscation, so this link cannot be imported");
  }
  parts.requireOneOf('security', 'which says how the connection is secured',
      const <String>{'reality'});

  final String flow = parts.requireOneOf(
      'flow', 'which selects the VLESS sub-protocol', const <String>{_flow});
  final String serverName = parts.require(
      'sni', 'which is the name REALITY fronts and cannot be guessed');
  final String fingerprint =
      parts.require('fp', 'which selects the uTLS ClientHello to imitate');
  if (!_fingerprints.contains(fingerprint)) {
    final List<String> sorted = _fingerprints.toList()..sort();
    parts.refuse("fp is `$fingerprint`, which is not one of sing-box 1.14's "
        'uTLS fingerprints (${sorted.join(', ')})');
  }
  final String publicKey =
      parts.require('pbk', 'which REALITY cannot connect without');
  _checkPublicKey(parts, publicKey);
  final String shortId =
      parts.require('sid', 'which REALITY cannot connect without');
  _checkShortId(parts, shortId);

  return VlessRealityOutbound(
    tag: tag,
    server: parts.host,
    serverPort: parts.port,
    profileName: parts.name,
    uuid: parts.credential,
    flow: flow,
    serverName: serverName,
    fingerprint: fingerprint,
    publicKey: publicKey,
    shortId: shortId,
  );
}

/// 32 raw bytes, unpadded base64url -- exactly what `_b64url_encode` in
/// vpnctl/reality_key.py produces, which is always 43 characters.
///
/// Checked here rather than left to sing-box because the way this goes wrong
/// is silent: a query parser that decodes `+` as a space (which is why
/// share_uri.dart does not use `Uri.queryParameters`) yields a key of the
/// right length that simply does not match the server's, and the handshake
/// then fails with a TLS error that says nothing about a key.
void _checkPublicKey(ShareUriParts parts, String value) {
  const int expected = 43;
  if (value.length != expected) {
    parts.refuse('pbk is ${value.length} characters; a REALITY public key is '
        '$expected (32 bytes, unpadded base64url)');
  }
  for (final int unit in value.codeUnits) {
    final bool ok = (unit >= 0x41 && unit <= 0x5a) || // A-Z
        (unit >= 0x61 && unit <= 0x7a) || // a-z
        (unit >= 0x30 && unit <= 0x39) || // 0-9
        unit == 0x2d || // -
        unit == 0x5f; // _
    if (!ok) {
      parts.refuse('pbk is not unpadded base64url');
    }
  }
}

/// sing-box takes `short_id` as hex, at most 8 bytes. The server writes
/// `secrets.token_hex(8)`, so 16 characters.
void _checkShortId(ShareUriParts parts, String value) {
  if (value.length > 16 || value.length.isOdd) {
    parts.refuse('sid is ${value.length} hex characters; a REALITY short_id is '
        'an even number of them, at most 16 (8 bytes)');
  }
  for (final int unit in value.codeUnits) {
    final bool ok = (unit >= 0x30 && unit <= 0x39) || // 0-9
        (unit >= 0x61 && unit <= 0x66) || // a-f
        (unit >= 0x41 && unit <= 0x46); // A-F
    if (!ok) {
      parts.refuse('sid is not hexadecimal');
    }
  }
}

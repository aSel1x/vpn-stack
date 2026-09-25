// Share URIs built the way vpnctl/protocols/*.py builds them.
//
// Two kinds of URI live here and they are not interchangeable.
//
// SYNTHETIC, built by [buildShareUri]: the parameter lists below are
// transcriptions of the f-strings in vless_reality.py's and hysteria2.py's
// share(), and the builder edits them -- drop `pbk`, replace `security`, append
// a parameter the server does not write -- so "missing each required parameter"
// is nine variations rather than nine hand-written URIs that drift apart. Only a
// builder can do that, which is why these stay.
//
// GENERATED, reached through [fixtureShareUri]: the real URI, taken out of
// test/fixtures/user-export.json, which tests/test_json_contract.py generates by
// calling share() and then holds cli.py to. That is what closes the hole this
// file used to document and could not fix: the transcription was checked by
// nothing, so adding a parameter to share() left these tests green while every
// real link was refused -- the parser rejects parameters it does not know. The
// cross-check now lives in config_vless_test.dart and config_hysteria2_test.dart,
// which assert the generated URI's parameters against the lists below, in order.
//
// Not a _test.dart file: it holds no tests and `flutter test` should not collect
// it.
//
// The synthetic credentials are the shapes users_store.py really produces: a
// uuid4, two `secrets.token_hex(16)` strings, and `secrets.token_hex(8)` for the
// short id. None of them belongs to a real server.

import 'dart:convert';
import 'dart:io';

/// vless_reality.py's PORT.
const int vlessPort = 10443;

/// hysteria2.py's PORT.
const int hysteria2Port = 20443;

const String serverHost = '203.0.113.9';

const String vlessUuid = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';

/// 43 characters of unpadded base64url, which is what `_b64url_encode` in
/// vpnctl/reality_key.py produces for a 32-byte X25519 public key. Taken from
/// sing-box's own documentation example, so it is a shape nobody can mistake
/// for a live key.
const String realityPublicKey = 'jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0';

/// `secrets.token_hex(8)`.
const String realityShortId = '0123456789abcdef';

/// `secrets.token_hex(16)`.
const String hysteria2Password = '4f1c0b9a2e8d7c6b5a4938271605f4e3';

/// `secrets.token_hex(16)`.
const String obfsPassword = 'd41d8cd98f00b204e9800998ecf8427e';

/// SHA-256 of the DER certificate, uppercase hex with colons -- what
/// `Certificate.fingerprint()` produces in hysteria2.py's share().
const String certificatePin =
    'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:'
    'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89';

/// The masquerade hosts, which are structural constants in the two modules.
const String vlessSni = 'www.apple.com';
const String hysteria2Sni = 'bing.com';

/// Exactly the parameters vless_reality.py writes, in its order.
const List<List<String>> vlessShareParams = <List<String>>[
  <String>['encryption', 'none'],
  <String>['flow', 'xtls-rprx-vision'],
  <String>['security', 'reality'],
  <String>['sni', vlessSni],
  <String>['fp', 'chrome'],
  <String>['pbk', realityPublicKey],
  <String>['sid', realityShortId],
  <String>['type', 'tcp'],
  <String>['headerType', 'none'],
];

/// base64(SHA-256(SubjectPublicKeyInfo)) -- what `_spki_sha256()` produces in
/// hysteria2.py's share(), and the only pin sing-box can check.
const String certificateSpki = 'BzXhPQ2yVCkGDXK5dRJiTlIz3bMUwEZAfTZP1xhbQ0E=';

/// Exactly the parameters hysteria2.py writes, in its order.
///
/// `spki` is in here because it once was not: it was added to share() and this
/// list stayed as it was, so every test passed while every real link was refused
/// for carrying a parameter the parser did not know. Two things check it now --
/// test_protocols_share.py asserts the name set on the Python side, and
/// config_hysteria2_test.dart asserts this list against the generated URI in
/// test/fixtures/user-export.json, in order.
const List<List<String>> hysteria2ShareParams = <List<String>>[
  <String>['obfs', 'salamander'],
  <String>['obfs-password', obfsPassword],
  <String>['sni', hysteria2Sni],
  <String>['pinSHA256', certificatePin],
  <String>['spki', certificateSpki],
];

/// One share URI.
///
/// [change] edits the parameter list before it is written: a null value drops
/// the parameter, a non-null one replaces it, and a key the protocol does not
/// have is appended. That is how "missing each required parameter" is tested
/// without nine hand-written URIs that drift apart.
///
/// [fragment] is written verbatim, NOT escaped, because the thing under test
/// is how a percent-encoded name comes back.
String buildShareUri({
  required String scheme,
  required String credential,
  required String host,
  required int port,
  required List<List<String>> params,
  Map<String, String?> change = const <String, String?>{},
  String? fragment,
}) {
  final List<String> pairs = <String>[];
  for (final List<String> pair in params) {
    final String key = pair[0];
    if (change.containsKey(key)) {
      final String? replacement = change[key];
      if (replacement == null) continue;
      pairs.add('$key=$replacement');
    } else {
      pairs.add('$key=${pair[1]}');
    }
  }
  for (final MapEntry<String, String?> entry in change.entries) {
    final bool known = params.any((List<String> p) => p[0] == entry.key);
    final String? value = entry.value;
    if (!known && value != null) {
      pairs.add('${entry.key}=$value');
    }
  }
  final String authority = host.contains(':') ? '[$host]' : host;
  final String query = pairs.isEmpty ? '' : '?${pairs.join('&')}';
  final String tail = fragment == null ? '' : '#$fragment';
  return '$scheme://$credential@$authority:$port$query$tail';
}

String vlessUri({
  Map<String, String?> change = const <String, String?>{},
  String? fragment = 'asel1x',
  String host = serverHost,
  int port = vlessPort,
  String credential = vlessUuid,
}) =>
    buildShareUri(
      scheme: 'vless',
      credential: credential,
      host: host,
      port: port,
      params: vlessShareParams,
      change: change,
      fragment: fragment,
    );

String hysteria2Uri({
  Map<String, String?> change = const <String, String?>{},
  String? fragment = 'asel1x',
  String host = serverHost,
  int port = hysteria2Port,
  String credential = hysteria2Password,
}) =>
    buildShareUri(
      scheme: 'hysteria2',
      credential: credential,
      host: host,
      port: port,
      params: hysteria2ShareParams,
      change: change,
      fragment: fragment,
    );

// --------------------------------------------- the generated URIs, from cli.py

/// The share URI `vpnctl user export --json` really emitted for a protocol.
///
/// Read out of test/fixtures/user-export.json, which tests/test_json_contract.py
/// generates by calling the protocol's own share() and then asserts cli.py still
/// prints. So this is not a transcription of the format: it IS the format, and a
/// value change in share() -- `security`, `flow`, the obfs type, a new
/// parameter -- reaches these tests as a failure.
///
/// Throws rather than returning null when the protocol has no URI item: dnstt
/// deliberately emits `fields` and no URI at all, and a silent null there would
/// turn every assertion about it into a skip.
String fixtureShareUri(String protocol) {
  final File file = File('test/fixtures/user-export.json');
  if (!file.existsSync()) {
    throw StateError(
      'test/fixtures/user-export.json is missing. It is generated from '
      'vpnctl/cli.py: run `UPDATE_CONTRACT=1 uv run --frozen --with pytest '
      'pytest tests/test_json_contract.py` from the repository root.',
    );
  }
  final Map<String, Object?> payload =
      jsonDecode(file.readAsStringSync()) as Map<String, Object?>;
  final Map<String, Object?> protocols =
      payload['protocols']! as Map<String, Object?>;
  final List<Object?> items = protocols[protocol]! as List<Object?>;
  for (final Object? item in items) {
    final Object? uri = (item! as Map<String, Object?>)['uri'];
    if (uri is String) return uri;
  }
  throw StateError('no uri item for $protocol in test/fixtures/user-export.json');
}

/// The query of [uri], as `key=value` pairs IN ORDER and without decoding.
///
/// Order matters to the comparison this feeds: a set comparison would pass on a
/// share() that emitted the same names in a different order, and the point of
/// the transcribed lists above is that they describe the f-string. Undecoded
/// because `spki` is base64 whose `+` arrives percent-encoded, and decoding here
/// would hide whether it was encoded at all.
List<List<String>> shareUriQuery(String uri) {
  final int mark = uri.indexOf('?');
  if (mark < 0) return const <List<String>>[];
  final int hash = uri.indexOf('#', mark);
  final String query =
      hash < 0 ? uri.substring(mark + 1) : uri.substring(mark + 1, hash);
  return <List<String>>[
    for (final String pair in query.split('&'))
      if (pair.isNotEmpty)
        <String>[
          pair.substring(0, pair.indexOf('=')),
          pair.substring(pair.indexOf('=') + 1),
        ],
  ];
}

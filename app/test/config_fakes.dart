// Share URIs built the way vpnctl/protocols/*.py builds them.
//
// The parameter lists below are transcriptions of the f-strings in
// vless_reality.py's and hysteria2.py's share(): same parameters, same order,
// same separators. That is the point -- a test that invents its own URI proves
// the parser can read what the test author imagined, which is not the format
// anybody's phone is handed. Not a _test.dart file: it holds no tests and
// `flutter test` should not collect it.
//
// The credentials are the shapes users_store.py really produces: a uuid4, two
// `secrets.token_hex(16)` strings, and `secrets.token_hex(8)` for the short id.
// None of them belongs to a real server.

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
/// This list is transcribed by hand and nothing cross-checks it against the
/// Python, which is the known weak point of these fixtures: add a parameter to
/// share() and these tests stay green while every real link is refused, because
/// the parser rejects parameters it does not know. `spki` is here because that
/// happened -- the guard is now a test on the Python side asserting this exact
/// name set, which fails and names this file.
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

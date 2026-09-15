// Splitting a share URI into parts, once, for both schemes.
//
// Not `Uri.parse`. Two reasons, and both have bitten somebody:
//
//   * `Uri.queryParameters` decodes with the FORM rules, which turn `+` into a
//     space. A REALITY public key is base64 and a Hysteria2 password is
//     arbitrary; one `+` and the credential handed to sing-box is not the one
//     the server issued, with no error anywhere -- the handshake just fails.
//     Query values here go through `Uri.decodeComponent`, which is RFC 3986 and
//     leaves `+` alone.
//   * `Uri.fragment` normalises rather than decodes, so whether `#my%20phone`
//     comes back as `my phone` or `my%20phone` is a property of the SDK. The
//     fragment is cut out of the raw string and decoded exactly once, here.
//
// It is also strict where `Uri` is permissive: a duplicated parameter is a
// refusal, not a last-one-wins.

import 'errors.dart';

/// The scheme of [text], lowercased.
///
/// Throws rather than returning null: a string with no `://` is not a share
/// URI at all, and the caller has nothing useful to do with that but say so.
String shareUriScheme(String text) {
  final String trimmed = text.trim();
  final int mark = trimmed.indexOf('://');
  if (mark <= 0) {
    // The input is not echoed. It may be a password somebody pasted into the
    // wrong box, and this string ends up in logs.
    throw ShareUriException(
      'the share URI (${trimmed.length} characters)',
      'no scheme: expected <scheme>://<credential>@<host>:<port>',
    );
  }
  return trimmed.substring(0, mark).toLowerCase();
}

/// One share URI, split and decoded.
class ShareUriParts {
  const ShareUriParts({
    required this.scheme,
    required this.where,
    required this.credential,
    required this.host,
    required this.port,
    required this.params,
    required this.name,
  });

  final String scheme;

  /// The URI with the credential elided. Every message about this URI starts
  /// with it, so a person can tell which of several profiles failed.
  final String where;

  /// The userinfo: a VLESS UUID, a Hysteria2 password.
  final String credential;

  /// Bare, without the brackets an IPv6 literal carries in a URI. sing-box's
  /// `server` field wants the address itself.
  final String host;

  final int port;

  final Map<String, String> params;

  /// The `#fragment`, decoded. Null when there was none, and null when it was
  /// empty -- an empty label is not a name, and rendering one gives a list row
  /// with nothing in it.
  final String? name;

  Never refuse(String reason) => throw ShareUriException(where, reason);

  /// The value of [key], or a refusal that says what the parameter is for.
  ///
  /// [purpose] completes the sentence "no pbk parameter, ...", so write it as
  /// a clause: `which REALITY cannot connect without`.
  String require(String key, String purpose) {
    final String? value = params[key];
    if (value == null || value.isEmpty) {
      refuse('no $key parameter, $purpose');
    }
    return value;
  }

  /// Refuses a parameter this app does not know.
  ///
  /// Same stance as `rejectUnknown` in control/json.dart, for the same reason:
  /// a parameter nobody here reads may be the one that says the credential
  /// changed shape, and importing the rest as if it were not there is how a
  /// profile silently connects to the wrong thing. It also keeps a URI from
  /// some other panel -- `insecure=1`, `mport=`, `alpn=` -- from being
  /// half-parsed into a config that looks like this server's and is not.
  void rejectUnknownParameters(Set<String> known) {
    final List<String> unknown =
        params.keys.where((String k) => !known.contains(k)).toList()..sort();
    if (unknown.isNotEmpty) {
      refuse('parameter(s) this app does not know: ${unknown.join(', ')}. '
          'Either the server is newer than the app, or this URI came from '
          'somewhere else');
    }
  }

  /// The value of [key] constrained to [allowed].
  String requireOneOf(String key, String purpose, Set<String> allowed) {
    final String value = require(key, purpose);
    if (!allowed.contains(value)) {
      // The value IS echoed here, and only here: these are structural
      // constants (`tcp`, `reality`, `chrome`), never a credential.
      final List<String> sorted = allowed.toList()..sort();
      refuse('$key is `$value`, and this app only imports '
          '${sorted.map((String v) => '`$v`').join(' or ')}');
    }
    return value;
  }
}

/// Splits [text], which must carry [scheme].
ShareUriParts splitShareUri(String text, {required String scheme}) {
  final String trimmed = text.trim();
  final String marker = '$scheme://';
  String where = '$scheme://…';
  Never refuse(String reason) => throw ShareUriException(where, reason);

  if (!trimmed.startsWith(marker)) {
    refuse('not a $scheme URI');
  }
  String rest = trimmed.substring(marker.length);

  // Fragment first: it is everything after the FIRST `#`, and it may itself
  // contain a `?`. Cutting the query first would eat half a profile name.
  final int hash = rest.indexOf('#');
  final String rawName = hash >= 0 ? rest.substring(hash + 1) : '';
  if (hash >= 0) {
    rest = rest.substring(0, hash);
  }
  final String decodedName = _decode(rawName, refuse, 'the #fragment');
  final String? name = decodedName.isEmpty ? null : decodedName;

  final int mark = rest.indexOf('?');
  final String query = mark >= 0 ? rest.substring(mark + 1) : '';
  if (mark >= 0) {
    rest = rest.substring(0, mark);
  }

  // The credential is split off BEFORE the path is looked for, not after: a
  // password with a `/` in it would otherwise be read as the start of a path
  // and refused with a sentence about paths.
  final int at = rest.lastIndexOf('@');
  if (at < 0) {
    refuse('no credential: expected $scheme://<credential>@<host>:<port>');
  }
  final String credential =
      _decode(rest.substring(0, at), refuse, 'the credential');
  if (credential.isEmpty) {
    refuse('the credential before @ is empty');
  }

  // Neither share() emits a path. A URI that has one is not this server's, and
  // silently dropping it would import a profile that points somewhere else.
  String authority = rest.substring(at + 1);
  final int slash = authority.indexOf('/');
  if (slash >= 0) {
    if (authority.substring(slash) != '/') {
      refuse('has a path, and neither share link this server issues has one');
    }
    authority = authority.substring(0, slash);
  }
  final String host;
  final String portText;
  if (authority.startsWith('[')) {
    final int close = authority.indexOf(']');
    if (close < 0) {
      refuse('the IPv6 literal after @ is missing its closing bracket');
    }
    host = authority.substring(1, close);
    final String tail = authority.substring(close + 1);
    if (!tail.startsWith(':')) {
      refuse('no port after the IPv6 literal');
    }
    portText = tail.substring(1);
  } else {
    // More than one colon and no brackets means a bare IPv6 literal, and
    // lastIndexOf would split inside the address: `2001:db8::1` became host
    // `2001:db8:` on port 1 -- a structurally valid config that can never
    // connect, which is the failure this whole function is written to refuse.
    if (authority.indexOf(':') != authority.lastIndexOf(':')) {
      refuse(
        'an IPv6 address must be bracketed as [address]:port; '
        'without brackets the port cannot be told from the address',
      );
    }
    final int colon = authority.lastIndexOf(':');
    if (colon < 0) {
      // Both share() functions interpolate a port unconditionally, so a URI
      // without one is not from this server -- and guessing 443 would produce
      // a profile that fails to connect for a reason nobody can see.
      refuse('no port: expected <host>:<port> after @');
    }
    host = authority.substring(0, colon);
    portText = authority.substring(colon + 1);
  }
  if (host.isEmpty) {
    refuse('the host is empty');
  }
  final int? port = int.tryParse(portText);
  if (port == null || port < 1 || port > 65535) {
    refuse('the port is not a number between 1 and 65535');
  }

  where = host.contains(':')
      ? '$scheme://…@[$host]:$port'
      : '$scheme://…@$host:$port';

  final Map<String, String> params = <String, String>{};
  for (final String pair in query.split('&')) {
    if (pair.isEmpty) continue;
    final int eq = pair.indexOf('=');
    if (eq <= 0) {
      refuse('the query has a segment that is not key=value');
    }
    final String key = _decode(pair.substring(0, eq), refuse, 'a parameter name');
    final String value =
        _decode(pair.substring(eq + 1), refuse, 'the value of `$key`');
    if (params.containsKey(key)) {
      // Last-one-wins is how two different short_ids end up as one working
      // profile on the laptop and a broken one on the phone.
      refuse('the parameter `$key` appears more than once');
    }
    params[key] = value;
  }

  return ShareUriParts(
    scheme: scheme,
    where: where,
    credential: credential,
    host: host,
    port: port,
    params: params,
    name: name,
  );
}

String _decode(String value, Never Function(String) refuse, String what) {
  try {
    return Uri.decodeComponent(value);
  } catch (_) {
    // ArgumentError for a truncated escape, FormatException for bytes that are
    // not UTF-8. Neither says which part of the URI it came from, which is the
    // whole reason this wrapper exists.
    refuse('$what is not valid percent-encoding');
  }
}

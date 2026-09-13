// Reading a --json payload strictly, and saying where it went wrong.
//
// Every failure here names its own location -- `users[2].name: expected a
// string, got null` -- because the alternative is `as String?` and a null that
// flows on into a rendered profile. A half-parsed credential is worse than a
// refusal: it looks like it worked, and the person only finds out when the
// import fails on somebody else's phone. Same stance as users_store.load(),
// which refuses a database it does not fully understand rather than dropping
// the fields it does not recognise.

import 'dart:convert';
import 'dart:typed_data';

/// A payload this app cannot read.
///
/// Deliberately knows nothing about argv or SSH: the models are pure, so they
/// are testable on a literal map. [Vpnctl] catches these and re-throws them as
/// the argv-bearing errors in errors.dart, which is where the raw payload and
/// the command line are attached.
sealed class PayloadException implements Exception {
  const PayloadException();

  /// One located sentence. Goes straight into the error a person sees.
  String get reason;

  @override
  String toString() => reason;
}

/// A field is missing, or is not the type this app can use.
final class PayloadFormatException extends PayloadException {
  const PayloadFormatException(this.reason);

  @override
  final String reason;
}

/// A field nobody here knows about.
///
/// Its own class because the remedy differs and is stateable -- the server is
/// newer than the app -- and because [Vpnctl] turns it into the schema error
/// that says so by name.
final class UnknownFieldException extends PayloadException {
  const UnknownFieldException(this.where, this.field);

  /// The object that carried it: `users[2]`, `protocols.dnstt[0]`, or the empty
  /// string for the payload itself.
  final String where;

  final String field;

  @override
  String get reason => '${where.isEmpty ? 'the payload' : where} has a field '
      'this app does not know ($field)';
}

/// Joins a location and a key the way every message in this file does.
String jsonPath(String where, String key) =>
    where.isEmpty ? key : '$where.$key';

String _describe(Object? value) {
  if (value == null) return 'null';
  if (value is String) return 'a string';
  if (value is bool) return 'a boolean';
  if (value is num) return 'a number';
  if (value is List) return 'a list';
  if (value is Map) return 'an object';
  return '$value';
}

Never _wrongType(String path, String expected, Object? got) =>
    throw PayloadFormatException(
        '$path: expected $expected, got ${_describe(got)}');

/// The value at [key], or a located failure if it is absent.
///
/// Absent and null are kept apart on purpose: a missing key means the server
/// does not speak this field at all, a null means it does and had nothing to
/// say. Only one of those is an upgrade problem.
Object? _present(Map<String, Object?> json, String key, String where) {
  if (!json.containsKey(key)) {
    throw PayloadFormatException('${jsonPath(where, key)} is missing');
  }
  return json[key];
}

Map<String, Object?> asObject(Object? value, String where) {
  if (value is Map<String, Object?>) return value;
  _wrongType(where.isEmpty ? 'the payload' : where, 'an object', value);
}

List<Object?> asList(Object? value, String where) {
  if (value is List<Object?>) return value;
  _wrongType(where, 'a list', value);
}

String readString(Map<String, Object?> json, String key, {String where = ''}) {
  final Object? value = _present(json, key, where);
  if (value is String) return value;
  _wrongType(jsonPath(where, key), 'a string', value);
}

/// A key that may be absent, or present and null. Anything else is still an
/// error: a wrong type silently read as "not set" is how an empty screen gets
/// mistaken for an empty server.
String? readNullableString(Map<String, Object?> json, String key,
    {String where = ''}) {
  if (!json.containsKey(key)) return null;
  final Object? value = json[key];
  if (value == null) return null;
  if (value is String) return value;
  _wrongType(jsonPath(where, key), 'a string or null', value);
}

bool readBool(Map<String, Object?> json, String key, {String where = ''}) {
  final Object? value = _present(json, key, where);
  if (value is bool) return value;
  _wrongType(jsonPath(where, key), 'a boolean', value);
}

/// Ints only. Python emits `3`, never `3.0`, and accepting a double here would
/// mean a user count that renders as "2.0".
int readInt(Map<String, Object?> json, String key, {String where = ''}) {
  final Object? value = _present(json, key, where);
  if (value is int) return value;
  _wrongType(jsonPath(where, key), 'an integer', value);
}

List<String> readStringList(Map<String, Object?> json, String key,
    {String where = ''}) {
  final Object? value = _present(json, key, where);
  return _strings(value, jsonPath(where, key));
}

/// Absent or null both give null, so a caller can tell "the server did not run
/// this step" from "it ran and produced nothing". `apply`'s `config_changed`
/// is exactly that distinction: null means it could not compare, `[]` means it
/// compared and nothing changed.
List<String>? readNullableStringList(Map<String, Object?> json, String key,
    {String where = ''}) {
  if (!json.containsKey(key) || json[key] == null) return null;
  return _strings(json[key], jsonPath(where, key));
}

List<String> _strings(Object? value, String path) {
  final List<Object?> raw = asList(value, path);
  final List<String> out = <String>[];
  for (int i = 0; i < raw.length; i++) {
    final Object? element = raw[i];
    if (element is! String) {
      _wrongType('$path[$i]', 'a string', element);
    }
    out.add(element);
  }
  return out;
}

Map<String, Object?> readObject(Map<String, Object?> json, String key,
    {String where = ''}) {
  return asObject(_present(json, key, where), jsonPath(where, key));
}

List<Object?> readList(Map<String, Object?> json, String key,
    {String where = ''}) {
  return asList(_present(json, key, where), jsonPath(where, key));
}

/// Base64 that vpnctl produced with `base64.b64encode`.
///
/// A decode failure is reported as this field's failure rather than as a bare
/// FormatException from dart:convert, which says nothing about which of the
/// three bundles was truncated.
Uint8List readBase64(Map<String, Object?> json, String key,
    {String where = ''}) {
  final String text = readString(json, key, where: where);
  try {
    return base64Decode(text);
  } on FormatException catch (e) {
    throw PayloadFormatException(
        '${jsonPath(where, key)}: not valid base64 (${e.message})');
  }
}

/// Refuses any key [known] does not list.
///
/// By name, and refusing rather than ignoring: a field this app cannot see may
/// be the one that says a credential changed shape, and rendering the rest as
/// if nothing happened is the failure this whole file exists to avoid.
void rejectUnknown(Map<String, Object?> json, Set<String> known,
    {String where = ''}) {
  for (final String key in json.keys) {
    if (!known.contains(key)) {
      throw UnknownFieldException(where, key);
    }
  }
}

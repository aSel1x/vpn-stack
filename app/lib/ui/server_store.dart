import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'ports.dart';

/// Where the configured servers live between launches.
///
/// One blob under one key rather than a row per server: the list is read and
/// written whole, and a partial write that leaves three servers where there
/// were four is a failure mode worth not having.
///
/// A [ServerProfile] holds no credential -- that is the entire reason
/// [SshCredential] is a separate type -- so this store is not, strictly, a
/// secret store. It uses the secure one anyway because it is the only
/// persistence in pubspec.yaml, and because the list of servers somebody
/// tunnels through is itself worth not leaving in plain preferences.
class SecureServerStore implements ServerStore {
  SecureServerStore({FlutterSecureStorage? storage})
      : _storage = storage ?? FlutterSecureStorage();

  final FlutterSecureStorage _storage;

  /// The storage key, and deliberately still `v1` after the schema went to 2.
  ///
  /// Bumping it would make an older build of the app find NOTHING under its own
  /// key and show an empty server list -- a silent downgrade that looks like
  /// data loss. Keeping one key means an older build reads this blob, sees
  /// schema 2, and refuses by name with the sentence below. Loud beats empty.
  static const String _key = 'vpn_stack.servers.v1';

  /// Bumped when the shape changes. Read refuses a higher number by name,
  /// exactly as `users_store.load()` does on the server: dropping a field this
  /// code does not know about would let the next save write the record back
  /// without it.
  ///
  /// 2 added `host_key` -- the pinned SSH host key, without which this app
  /// connects to whatever answers on port 22.
  static const int _schema = 2;

  @override
  Future<List<ServerProfile>> load() async {
    final String? raw = await _storage.read(key: _key);
    if (raw == null || raw.trim().isEmpty) {
      return <ServerProfile>[];
    }
    final Object? decoded = jsonDecode(raw);
    if (decoded is! Map<String, Object?>) {
      throw FormatException(
        'the saved server list is not an object; it was written by something '
        'other than this app and is not being guessed at',
      );
    }
    final int schema = decoded['schema'] as int? ?? 0;
    if (schema > _schema) {
      throw FormatException(
        'the saved server list is schema $schema and this build understands '
        '$_schema. The list was written by a newer version of the app -- this '
        'code is older than the data, and a record it cannot read whole is a '
        'record it must not write back: a pinned host key or a credential '
        'dropped on the way through is one this build would never know it '
        'lost. Update the app. Nothing was changed.',
      );
    }
    final List<Object?> rows =
        decoded['servers'] as List<Object?>? ?? const <Object?>[];
    // An OLDER blob needs no migration and gets none: schema 1 had no
    // `host_key`, so every record it holds reads back with no pin and the next
    // connection asks the first-contact question. That is the only honest
    // reading -- a pin cannot be invented for a key this device never saw --
    // and it is the safe one, because "never asked" prompts while "trusted"
    // would not. The save that follows writes schema 2, so it happens once.
    return rows
        .map((Object? e) => ServerProfile.fromJson(e! as Map<String, Object?>))
        .toList();
  }

  @override
  Future<void> save(List<ServerProfile> servers) async {
    final String blob = jsonEncode(<String, Object?>{
      'schema': _schema,
      'servers': servers.map((ServerProfile s) => s.toJson()).toList(),
    });
    await _storage.write(key: _key, value: blob);
  }
}

/// For tests, and for a platform where the secure store is unavailable.
///
/// Not a silent fallback: a store that forgets everything on quit while looking
/// like one that does not is worse than an error message, so whoever swaps this
/// in has to do it deliberately.
class InMemoryServerStore implements ServerStore {
  InMemoryServerStore([List<ServerProfile> initial = const <ServerProfile>[]])
      : _servers = List<ServerProfile>.of(initial);

  List<ServerProfile> _servers;

  @override
  Future<List<ServerProfile>> load() async => List<ServerProfile>.of(_servers);

  @override
  Future<void> save(List<ServerProfile> servers) async {
    _servers = List<ServerProfile>.of(servers);
  }
}

// What `vpnctl ... --json` answers, as types.
//
// One class per payload, hand-written fromJson, no generator: this tree has no
// Dart toolchain on the machines that edit it, and a model that can only be
// checked by running a code generator in CI is a model nobody reads. The field
// names are the server's, translated once, here -- so when cli.py renames a
// key exactly one file fails to parse and says which key it was.

import 'dart:typed_data';

import 'json.dart';

/// What `apply` returns, and what every mutating command inlines into its own
/// payload: `user add` emits `user` beside these keys, `protocol on` emits
/// `changed` beside them.
class ApplyResult {
  const ApplyResult({
    required this.rendered,
    required this.enabledProtocols,
    required this.restarted,
    required this.configChanged,
    required this.convergePending,
    this.teardown,
    this.ready,
    this.portsReady,
    this.firewall,
    this.ikev2Forwarding,
    this.ikev2Reconcile,
    this.unknownKeys = const <String>[],
  });

  /// The keys `apply()` in cli.py puts in its result. The last five are
  /// conditional: everything from `teardown` down is absent when the command
  /// rendered without converging, and `ikev2_*` only appear when ikev2 is both
  /// enabled and running.
  static const Set<String> keys = <String>{
    'rendered',
    'enabled_protocols',
    'restarted',
    'config_changed',
    'converge_pending',
    'teardown',
    'ready',
    'ports_ready',
    'firewall',
    'ikev2_forwarding',
    'ikev2_reconcile',
  };

  /// [consumed] are the keys the enclosing command owns -- `user`, `enabled`,
  /// `changed`. They are not apply's, and they are not unknown either.
  factory ApplyResult.fromJson(
    Map<String, Object?> json, {
    Set<String> consumed = const <String>{},
    String where = '',
  }) {
    final List<String> unknown = <String>[];
    for (final String key in json.keys) {
      if (!keys.contains(key) && !consumed.contains(key)) {
        unknown.add(key);
      }
    }
    unknown.sort();

    return ApplyResult(
      rendered: readString(json, 'rendered', where: where),
      // `enabled_protocols`, never `enabled`. The two collided once inside
      // emit(**result) and made every `user enable` raise TypeError, which is
      // why the server's key is the longer one and `enabled` at this level
      // belongs to the *user*.
      enabledProtocols: readStringList(json, 'enabled_protocols', where: where),
      restarted: readBool(json, 'restarted', where: where),
      // null and [] are different answers: null is "there was no live tree to
      // compare against, so everything was converged", [] is "compared,
      // nothing changed, nothing bounced".
      configChanged:
          readNullableStringList(json, 'config_changed', where: where),
      convergePending: readBool(json, 'converge_pending', where: where),
      teardown: readNullableString(json, 'teardown', where: where),
      ready: readNullableStringList(json, 'ready', where: where),
      portsReady: readNullableBool(json, 'ports_ready', where: where),
      firewall: readNullableStringList(json, 'firewall', where: where),
      ikev2Forwarding:
          readNullableString(json, 'ikev2_forwarding', where: where),
      ikev2Reconcile: json.containsKey('ikev2_reconcile')
          ? Ikev2Reconcile.fromJson(
              readObject(json, 'ikev2_reconcile', where: where),
              where: jsonPath(where, 'ikev2_reconcile'),
            )
          : null,
      unknownKeys: unknown,
    );
  }

  /// The candidate directory that was promoted, e.g. `rendered-1757340000`.
  final String rendered;

  final List<String> enabledProtocols;

  /// False when the caller asked for `--no-restart`, and also when the server
  /// refused to converge because VPN_STATE_DIR pointed somewhere else.
  final bool restarted;

  /// Services whose rendered input changed, or null when the server could not
  /// tell and therefore converged everything.
  final List<String>? configChanged;

  /// A tree is on disk that no container is running yet. The next `apply`
  /// recreates every service. Worth surfacing: until it happens, sing-box is
  /// still serving the previous keys and every freshly exported profile fails.
  final bool convergePending;

  final String? teardown;

  /// One line per port that never bound, or a single "all N port(s) bound".
  /// `apply` only *warns* about these, so a caller that wants to know whether
  /// the server is really serving has to read them. Prose, for a person: the
  /// verdict is [portsReady].
  final List<String>? ready;

  /// The server's own answer to "did every expected port bind?", from
  /// `composectl.wait_ready` rather than from its wording.
  ///
  /// Null means the server did not say: one too old to emit the key, or an
  /// apply that rendered without converging and therefore waited for nothing.
  final bool? portsReady;

  final List<String>? firewall;
  final String? ikev2Forwarding;
  final Ikev2Reconcile? ikev2Reconcile;

  /// Keys this app does not know, named rather than dropped -- but not fatal.
  ///
  /// This is the one place where an unrecognised field is tolerated, and the
  /// reason is that this payload is a receipt: `user add` has already written
  /// users.json and converged the containers by the time it is printed.
  /// Refusing to parse it would report a failure for something that succeeded,
  /// and the obvious retry then fails with "already exists". Everywhere else --
  /// a user row, a share item, status -- an unknown field is refused by name,
  /// because there the risk runs the other way: rendering a record whose shape
  /// has changed.
  final List<String> unknownKeys;

  /// True when the ports the server expected to serve are all bound.
  ///
  /// [portsReady] is the server's own boolean and wins whenever it is there.
  /// The English in [ready] is written for a person -- rewording
  /// `composectl.wait_ready`'s success note is a change nobody would think of
  /// as breaking a client -- so deciding health by matching "all " against it
  /// meant the app could start calling a healthy server dead on a server-side
  /// edit that touched no contract. That is the fragility `ports_ready` was
  /// added to remove.
  ///
  /// The prose parse survives only for a server that predates the key, which
  /// arrived with the rest of apply's converge verdicts (`teardown_ok`,
  /// `firewall_ok`, `forwarding_ok`). Delete it -- and make [portsReady] the
  /// whole of this getter -- once no server this app is pointed at is older
  /// than those, because until then an upgraded app against an un-upgraded
  /// server would report every apply as "ports never bound".
  bool get portsBound =>
      portsReady ??
      (ready != null && ready!.length == 1 && ready!.single.startsWith('all '));
}

/// `apply`'s IKEv2 reconciliation: certificates made to match the enabled
/// users, from observed truth rather than remembered intent.
class Ikev2Reconcile {
  const Ikev2Reconcile({
    required this.added,
    required this.revoked,
    required this.failed,
    this.skipped,
    this.error,
  });

  factory Ikev2Reconcile.fromJson(Map<String, Object?> json,
      {String where = ''}) {
    // Two shapes, and the server picks by whether it could run at all.
    if (json.containsKey('skipped')) {
      rejectUnknown(json, const <String>{'skipped', 'error'}, where: where);
      return Ikev2Reconcile(
        added: const <String>[],
        revoked: const <String>[],
        failed: const <String>[],
        skipped: readString(json, 'skipped', where: where),
        error: readNullableString(json, 'error', where: where),
      );
    }
    rejectUnknown(json, const <String>{'added', 'revoked', 'failed'},
        where: where);
    return Ikev2Reconcile(
      added: readStringList(json, 'added', where: where),
      revoked: readStringList(json, 'revoked', where: where),
      failed: readStringList(json, 'failed', where: where),
    );
  }

  final List<String> added;
  final List<String> revoked;

  /// Names whose certificate could not be issued or revoked. A name in here
  /// after a `user rm` means a working certificate is still out there; the
  /// server keeps it in `revoke_pending` and retries on the next apply.
  final List<String> failed;

  /// Why nothing was done -- the container is down, or `--listclients` failed.
  /// Not an error: reconciliation that cannot observe the truth deliberately
  /// does nothing rather than guessing.
  final String? skipped;

  final String? error;

  bool get ran => skipped == null;
}

/// `vpnctl status`.
class ServerStatus {
  const ServerStatus({
    required this.stateDir,
    required this.isServer,
    required this.rendered,
    required this.enabled,
    required this.revokePending,
    required this.users,
    required this.usersEnabled,
    required this.ikev2Running,
  });

  factory ServerStatus.fromJson(Map<String, Object?> json,
      {String where = ''}) {
    rejectUnknown(
      json,
      const <String>{
        'state_dir',
        'is_server',
        'rendered',
        'enabled',
        'revoke_pending',
        'users',
        'users_enabled',
        'ikev2_running',
      },
      where: where,
    );
    return ServerStatus(
      stateDir: readString(json, 'state_dir', where: where),
      isServer: readBool(json, 'is_server', where: where),
      rendered: readNullableString(json, 'rendered', where: where),
      // status calls this `enabled`; apply calls the same list
      // `enabled_protocols`. Both are load-bearing names and neither is going
      // to be renamed to match the other, so they are translated separately.
      enabled: readStringList(json, 'enabled', where: where),
      revokePending: readStringList(json, 'revoke_pending', where: where),
      users: readInt(json, 'users', where: where),
      usersEnabled: readInt(json, 'users_enabled', where: where),
      ikev2Running: readBool(json, 'ikev2_running', where: where),
    );
  }

  final String stateDir;

  /// False means the state directory is not there, so every mutating command
  /// will refuse. Shown rather than hidden: the alternative is a UI where
  /// every button fails for a reason it never states.
  final bool isServer;

  /// The live rendered tree, or null when nothing has been applied yet.
  final String? rendered;

  final List<String> enabled;

  /// Revocations the server has not been able to run. A name in here means
  /// somebody's IKEv2 certificate still works after they were removed.
  final List<String> revokePending;

  final int users;
  final int usersEnabled;
  final bool ikev2Running;
}

/// One row of `vpnctl user list`.
class VpnUser {
  const VpnUser({
    required this.name,
    required this.enabled,
    required this.ikev2Provisioned,
    required this.createdAt,
    this.secrets,
  });

  factory VpnUser.fromJson(Map<String, Object?> json, {String where = ''}) {
    rejectUnknown(
      json,
      const <String>{
        'name',
        'enabled',
        'ikev2_provisioned',
        'created_at',
        // Only with --show-secrets. Known here so that asking for them is not
        // an upgrade error; absent from the model when they were not asked for.
        'vless_uuid',
        'hysteria2_password',
        'l2tp_password',
      },
      where: where,
    );
    return VpnUser(
      name: readString(json, 'name', where: where),
      enabled: readBool(json, 'enabled', where: where),
      ikev2Provisioned: readBool(json, 'ikev2_provisioned', where: where),
      createdAt: readString(json, 'created_at', where: where),
      secrets: UserSecrets.fromJson(json, where: where),
    );
  }

  final String name;
  final bool enabled;

  /// Whether the container really holds a certificate for this name, as
  /// observed by the last reconcile -- not an intention recorded when the user
  /// was added.
  final bool ikev2Provisioned;

  /// The server's own string, left unparsed. Nothing here does arithmetic on
  /// it, and parsing a format nobody promised is a crash for a label.
  final String createdAt;

  /// Only present when the caller asked for `--show-secrets`.
  final UserSecrets? secrets;
}

/// The credentials `user list --show-secrets` adds to a row.
///
/// Its own type so that holding a [VpnUser] is not the same as holding a
/// password: a list built without `--show-secrets` cannot accidentally be
/// logged with one.
class UserSecrets {
  const UserSecrets({
    required this.vlessUuid,
    required this.hysteria2Password,
    required this.l2tpPassword,
  });

  /// Null when the row carries none of the three. All three or none: a row
  /// with one of them is a database that lost a credential, and saying so
  /// beats rendering a share card with a blank field in it.
  ///
  /// Note there is no `dnstt_password` here. `user list` does not emit it at
  /// any verbosity; it reaches the app through `user export` only.
  static UserSecrets? fromJson(Map<String, Object?> json, {String where = ''}) {
    const List<String> names = <String>[
      'vless_uuid',
      'hysteria2_password',
      'l2tp_password',
    ];
    final int present = names.where(json.containsKey).length;
    if (present == 0) return null;
    if (present != names.length) {
      final List<String> missing =
          names.where((String n) => !json.containsKey(n)).toList();
      throw PayloadFormatException(
          '${where.isEmpty ? 'the user row' : where}: has some credentials but '
          'not others (missing ${missing.join(', ')})');
    }
    return UserSecrets(
      vlessUuid: readString(json, 'vless_uuid', where: where),
      hysteria2Password: readString(json, 'hysteria2_password', where: where),
      l2tpPassword: readString(json, 'l2tp_password', where: where),
    );
  }

  final String vlessUuid;
  final String hysteria2Password;
  final String l2tpPassword;
}

/// One row of `vpnctl protocol list`.
class ProtocolEntry {
  const ProtocolEntry({
    required this.name,
    required this.enabled,
    required this.ports,
    required this.kind,
    required this.summary,
    required this.notes,
  });

  factory ProtocolEntry.fromJson(Map<String, Object?> json,
      {String where = ''}) {
    rejectUnknown(
      json,
      const <String>{'name', 'enabled', 'ports', 'kind', 'summary', 'notes'},
      where: where,
    );
    return ProtocolEntry(
      name: readString(json, 'name', where: where),
      enabled: readBool(json, 'enabled', where: where),
      ports: readStringList(json, 'ports', where: where),
      kind: readString(json, 'kind', where: where),
      summary: readString(json, 'summary', where: where),
      notes: readString(json, 'notes', where: where),
    );
  }

  final String name;
  final bool enabled;

  /// Already formatted by the server: `10443/tcp`, `53/udp`. Kept as strings
  /// rather than re-parsed -- the app has no use for the halves, and splitting
  /// them here would be a second definition of a format the server owns.
  final List<String> ports;

  /// `singbox` (an inbound merged into the sing-box tree) or `compose` (its own
  /// container). Left as the server's string on purpose: a kind this app has
  /// never heard of is not a reason to refuse to list the protocols.
  final String kind;

  final String summary;

  /// Why it might be off. Shown when it is.
  final String notes;

  bool get isContainer => kind == 'compose';
}

/// One row of a settings form, in the order the server emitted it.
class ShareField {
  const ShareField(this.setting, this.value);

  final String setting;
  final String value;
}

/// One deliverable for one user, in exactly one of three shapes.
///
/// Sealed, not one class with four nullable fields, because picking the wrong
/// shape is a real bug this repository has already shipped: DNSTT-over-SSH has
/// no import format at all -- no URI scheme, nothing to scan -- and its
/// settings were once crammed into a `uri`. Every layer duly treated them as
/// one, producing a QR code nothing could read and a tappable link that
/// imported nothing. A switch over these three subtypes cannot compile while
/// ignoring one of them.
sealed class ShareItem {
  const ShareItem(this.label);

  /// Which platform or client this is for: "iOS/macOS", "VLESS + REALITY".
  final String label;

  /// Picks the shape by which key is present, and refuses when that is not
  /// exactly one. Guessing is the documented bug.
  static ShareItem fromJson(Map<String, Object?> json, {String where = ''}) {
    final bool hasUri = json.containsKey('uri');
    final bool hasFile = json.containsKey('filename');
    final bool hasFields = json.containsKey('fields');
    final int shapes =
        (hasUri ? 1 : 0) + (hasFile ? 1 : 0) + (hasFields ? 1 : 0);
    if (shapes != 1) {
      throw PayloadFormatException(
          '${where.isEmpty ? 'the share item' : where}: expected exactly '
          'one of uri, filename or fields, got $shapes. Rendering it as any '
          'one of them would be a guess.');
    }
    if (hasUri) {
      rejectUnknown(json, const <String>{'label', 'uri', 'png_b64'},
          where: where);
      return ShareUri(
        readString(json, 'label', where: where),
        readString(json, 'uri', where: where),
        // The server renders the QR, so the app needs no QR encoder and cannot
        // disagree with the CLI about what was encoded. Optional all the same:
        // the URI is the deliverable, the picture is a convenience, and losing
        // the picture must not lose the profile.
        qrPng: json.containsKey('png_b64')
            ? readBase64(json, 'png_b64', where: where)
            : null,
      );
    }
    if (hasFile) {
      rejectUnknown(json, const <String>{'label', 'filename', 'b64'},
          where: where);
      return ShareFile(
        readString(json, 'label', where: where),
        readString(json, 'filename', where: where),
        // Required, unlike the QR: a file item with no bytes is a download
        // button that saves nothing.
        readBase64(json, 'b64', where: where),
      );
    }
    rejectUnknown(json, const <String>{'label', 'fields'}, where: where);
    final List<Object?> rows = readList(json, 'fields', where: where);
    final String rowsPath = jsonPath(where, 'fields');
    final List<ShareField> fields = <ShareField>[];
    for (int i = 0; i < rows.length; i++) {
      final List<Object?> pair = asList(rows[i], '$rowsPath[$i]');
      if (pair.length != 2) {
        throw PayloadFormatException(
            '$rowsPath[$i]: expected a [setting, value] pair, got '
            '${pair.length} element(s)');
      }
      final Object? setting = pair[0];
      final Object? value = pair[1];
      if (setting is! String || value is! String) {
        throw PayloadFormatException(
            '$rowsPath[$i]: expected two strings');
      }
      fields.add(ShareField(setting, value));
    }
    return ShareFields(readString(json, 'label', where: where), fields);
  }
}

/// Something a client imports, and a QR code can carry.
final class ShareUri extends ShareItem {
  const ShareUri(super.label, this.uri, {this.qrPng});

  final String uri;

  /// A PNG of [uri], produced by the server, or null when it sent none.
  final Uint8List? qrPng;
}

/// A file to install: `.p12`, `.sswan`, `.mobileconfig`.
final class ShareFile extends ShareItem {
  const ShareFile(super.label, this.filename, this.content);

  final String filename;

  /// The bundle itself. The `.p12` has an empty password -- it is an
  /// unprotected private key, so whoever holds these bytes has VPN access.
  final Uint8List content;
}

/// Settings typed into a form by hand. No QR: there is nothing to scan them
/// with, and a QR of a settings blob is one that fails silently in somebody's
/// hands.
final class ShareFields extends ShareItem {
  const ShareFields(super.label, this.fields);

  final List<ShareField> fields;
}

/// `vpnctl user export`: everything one person can be handed.
class ShareBundle {
  const ShareBundle({
    required this.user,
    required this.host,
    required this.byProtocol,
    required this.failed,
  });

  factory ShareBundle.fromJson(Map<String, Object?> json, {String where = ''}) {
    rejectUnknown(json, const <String>{'user', 'host', 'protocols', 'failed'},
        where: where);
    final Map<String, Object?> raw =
        readObject(json, 'protocols', where: where);
    final String rawPath = jsonPath(where, 'protocols');
    // Insertion order is registry order, and jsonDecode preserves it. The
    // tunnel layer takes importUris in this order, so re-sorting here would
    // quietly change which protocol a client tries first.
    final Map<String, List<ShareItem>> byProtocol = <String, List<ShareItem>>{};
    raw.forEach((String name, Object? value) {
      final List<Object?> items = asList(value, jsonPath(rawPath, name));
      byProtocol[name] = <ShareItem>[
        for (int i = 0; i < items.length; i++)
          ShareItem.fromJson(
            asObject(items[i], '${jsonPath(rawPath, name)}[$i]'),
            where: '${jsonPath(rawPath, name)}[$i]',
          ),
      ];
    });
    return ShareBundle(
      user: readString(json, 'user', where: where),
      host: readString(json, 'host', where: where),
      byProtocol: byProtocol,
      failed: readStringList(json, 'failed', where: where),
    );
  }

  final String user;

  /// The address the profiles were built against -- `--host`, or
  /// VPN_SERVER_HOST from the server's own .env.
  final String host;

  final Map<String, List<ShareItem>> byProtocol;

  /// Protocols whose export failed. vpnctl reports these rather than returning
  /// a bundle that is quietly missing the one profile somebody asked for, and
  /// so does this: [failed] being non-empty is why the payload can say
  /// `ok: false` on a command that exited 0.
  final List<String> failed;

  bool get complete => failed.isEmpty;

  /// Every importable URI, registry order preserved. What a tunnel engine is
  /// handed: choosing among them is sing-box's job, not this app's.
  List<String> get importUris => <String>[
        for (final List<ShareItem> items in byProtocol.values)
          for (final ShareItem item in items)
            if (item is ShareUri) item.uri,
      ];
}

/// `user add` and `user rm`.
class UserMutation {
  const UserMutation({required this.user, required this.apply});

  factory UserMutation.fromJson(Map<String, Object?> json,
      {String where = ''}) {
    return UserMutation(
      user: readString(json, 'user', where: where),
      apply: ApplyResult.fromJson(json,
          consumed: const <String>{'user'}, where: where),
    );
  }

  /// The name as the server recorded it.
  final String user;

  final ApplyResult apply;
}

/// `user enable` and `user disable`.
class UserEnablement {
  const UserEnablement({
    required this.user,
    required this.enabled,
    required this.apply,
  });

  factory UserEnablement.fromJson(Map<String, Object?> json,
      {String where = ''}) {
    return UserEnablement(
      user: readString(json, 'user', where: where),
      // The user's flag. `enabled_protocols` inside the same payload is
      // apply's list; the two share a prefix and nothing else.
      enabled: readBool(json, 'enabled', where: where),
      apply: ApplyResult.fromJson(json,
          consumed: const <String>{'user', 'enabled'}, where: where),
    );
  }

  final String user;
  final bool enabled;
  final ApplyResult apply;
}

/// `protocol on` and `protocol off`.
class ProtocolToggle {
  const ProtocolToggle({required this.changed, required this.apply});

  factory ProtocolToggle.fromJson(Map<String, Object?> json,
      {String where = ''}) {
    final bool changed = readBool(json, 'changed', where: where);
    if (!changed) {
      // Already in the asked-for state: vpnctl returns before rendering
      // anything, so there is no apply result in this payload and inventing an
      // empty one would claim a convergence that never ran.
      rejectUnknown(json, const <String>{'changed'}, where: where);
      return const ProtocolToggle(changed: false, apply: null);
    }
    return ProtocolToggle(
      changed: true,
      apply: ApplyResult.fromJson(json,
          consumed: const <String>{'changed'}, where: where),
    );
  }

  /// False when the protocol was already on (or already off).
  final bool changed;

  /// Null exactly when [changed] is false.
  final ApplyResult? apply;
}

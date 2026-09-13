import 'dart:typed_data';

import '../control/control.dart';
import '../provision/errors.dart';
import '../provision/ssh.dart';

/// What the UI needs that no other layer owns.
///
/// Everything the server says is already a type: `lib/control/` parses
/// `vpnctl ... --json` into [ServerStatus], [VpnUser], [ProtocolEntry] and the
/// sealed [ShareItem], and `lib/provision/` owns the step sequence. The screens
/// import those directly. Re-declaring any of them here would be a second
/// implementation of a format this repository already says must have exactly
/// one.
///
/// What is left is genuinely the UI's: which servers this device knows about,
/// the credential used to reach one, and the two holes nothing has filled yet
/// -- an SSH transport and somewhere to put a downloaded file.

/// Flattens whatever a layer threw into something a person can read.
///
/// Every exception this app raises on purpose already carries one sentence
/// written for a human. `toString()` would bury it behind the class name.
String describeError(Object error) {
  if (error is VpnctlException) {
    return error.message;
  }
  if (error is ProvisionException) {
    return error.message;
  }
  if (error is HostKeyError) {
    // Its toString() is already the sentence, so the fallback below would do --
    // but this is the one failure people will meet without knowing what it is,
    // and it is worth being explicit that the paragraph is deliberate and
    // arrives whole.
    return error.message;
  }
  if (error is UnimplementedError) {
    // Where this app keeps the sentence explaining what is missing.
    return error.message ?? error.toString();
  }
  if (error is StateError) {
    return error.message;
  }
  if (error is FormatException) {
    return error.message;
  }
  return error.toString();
}

/// One configured server. Holds no credential: see [SshCredential].
class ServerProfile {
  const ServerProfile({
    required this.id,
    required this.label,
    required this.host,
    this.sshUser = 'root',
    this.sshPort = 22,
    this.provisionedAt,
    this.hostKey,
  });

  factory ServerProfile.fromJson(Map<String, Object?> json) {
    final String? at = json['provisioned_at'] as String?;
    final String id = json['id']! as String;
    return ServerProfile(
      id: id,
      label: json['label']! as String,
      host: json['host']! as String,
      sshUser: json['ssh_user'] as String? ?? 'root',
      sshPort: json['ssh_port'] as int? ?? 22,
      provisionedAt: at == null ? null : DateTime.tryParse(at),
      hostKey: _readHostKey(json['host_key'], id),
    );
  }

  /// Absent for a record written by schema 1, which had nowhere to put one.
  /// That reads as "never asked", never as "trusted": the next connection shows
  /// the first-use question, which is the only honest thing a record with no
  /// key can produce.
  ///
  /// A record that HAS a key and cannot be parsed fails by name instead. The
  /// alternative -- reading a damaged pin as no pin -- silently demotes a pinned
  /// server back to trust-on-first-use, which is exactly the state somebody
  /// tampering with this store would want.
  static SshHostKey? _readHostKey(Object? stored, String id) {
    if (stored == null) {
      return null;
    }
    if (stored is! Map<String, Object?>) {
      throw FormatException(
        'the saved server "$id" has a host_key that is not an object',
      );
    }
    try {
      return SshHostKey.fromJson(stored);
    } on FormatException catch (bad) {
      throw FormatException(
        'the saved server "$id" has a damaged pinned host key: ${bad.message}',
      );
    }
  }

  final String id;
  final String label;

  /// The address clients connect to, and the one profiles are built against.
  final String host;

  final String sshUser;

  /// The port sshd is on, which is not necessarily 22 and is what the firewall
  /// step has to open. Allowing 22 on a box whose sshd listens elsewhere is
  /// precisely the lockout the deadman exists to survive.
  final int sshPort;

  /// Null until provisioning has succeeded once. A server that was added and
  /// never provisioned has no `vpnctl` on it, and saying so beats showing an
  /// SSH failure as though the box were broken.
  final DateTime? provisionedAt;

  /// The host key this device has accepted for this server, or null if nobody
  /// has been asked about one yet.
  ///
  /// Persisted, because a pin that lives only as long as the process is not a
  /// pin: every launch would be a first contact, the question would appear
  /// every day, and a question people see every day is a question people tap
  /// through -- at which point nothing can tell a rebuilt box from an impostor.
  /// Not a secret (it is the public half, and known_hosts is world-readable on
  /// every machine that has one), but it lives in the same store as the rest of
  /// the record because it is only meaningful next to the host it pins.
  final SshHostKey? hostKey;

  bool get provisioned => provisionedAt != null;

  bool get pinned => hostKey != null;

  String get target => '$sshUser@$host';

  /// `root@203.0.113.7:22`, which is what a host key question names.
  ///
  /// Not [target]: the port says which sshd answered, and a question that does
  /// not name it cannot be checked against the machine the person is looking
  /// at.
  String get sshTarget => '$sshUser@$host:$sshPort';

  ServerProfile copyWith({
    String? label,
    DateTime? provisionedAt,
    SshHostKey? hostKey,
  }) {
    return ServerProfile(
      id: id,
      label: label ?? this.label,
      host: host,
      sshUser: sshUser,
      sshPort: sshPort,
      provisionedAt: provisionedAt ?? this.provisionedAt,
      // Carried, not defaulted away. `markProvisioned` and "add only" both
      // copyWith one field, and a pin dropped by either would put the server
      // back to trust-on-first-use without anybody deciding that.
      hostKey: hostKey ?? this.hostKey,
    );
  }

  /// Drops the pin, so the next connection asks again.
  ///
  /// Its own method rather than a nullable flag on [copyWith], because
  /// `copyWith(hostKey: null)` means "keep" and would be read by everybody as
  /// "clear". The only caller is the deliberate menu action: a changed key is
  /// refused at the prompt, and this is the separate step somebody takes after
  /// deciding the box really was rebuilt.
  ServerProfile withoutHostKey() {
    return ServerProfile(
      id: id,
      label: label,
      host: host,
      sshUser: sshUser,
      sshPort: sshPort,
      provisionedAt: provisionedAt,
    );
  }

  Map<String, Object?> toJson() => <String, Object?>{
        'id': id,
        'label': label,
        'host': host,
        'ssh_user': sshUser,
        'ssh_port': sshPort,
        'provisioned_at': provisionedAt?.toIso8601String(),
        'host_key': hostKey?.toJson(),
      };
}

/// An SSH credential for one server.
///
/// Deliberately not a field of [ServerProfile]: the profile is the thing that
/// gets listed, persisted and put in a log, and a root password that rides
/// along in all three ends up somewhere nobody intended.
sealed class SshCredential {
  const SshCredential();

  /// Safe to show. Must never contain the secret -- a provisioning log that
  /// echoes the password is a log nobody can paste into an issue.
  String get describe;
}

final class SshPassword extends SshCredential {
  const SshPassword(this.password);

  final String password;

  @override
  String get describe => 'password';
}

final class SshPrivateKey extends SshCredential {
  const SshPrivateKey(this.pem, {this.passphrase});

  /// The private half, in PEM. Never a path: on a phone there is no file the
  /// app can read later, and a key this app kept a path to would be a key it
  /// could not use after the picker closed.
  final String pem;

  final String? passphrase;

  @override
  String get describe => passphrase == null || passphrase!.isEmpty
      ? 'private key'
      : 'private key (passphrase)';
}

/// Opens SSH connections to a server, given a credential.
///
/// The one hole neither `control/` nor `provision/` fills: both of them take
/// their transport injected, on purpose, and nothing in this repository yet
/// implements it. It is one interface with one method so that whoever writes
/// the dartssh2 implementation has a single small file to write and this app
/// has a single small file to fix if a signature there turns out to be
/// different from what somebody guessed.
///
/// Returning a [SshConnector] rather than a connection is not a detail: the
/// firewall step proves the rules it installed did not lock us out by opening a
/// SECOND, INDEPENDENT connection, so the thing handed around has to be able to
/// make a new one. Implementations must not pool.
///
/// Nothing in the UI calls this except ServerAccess (`access.dart`), which is
/// the one place a connector is paired with a host key policy. A connector on
/// its own is a `connect(HostKeyPolicy)` away from whatever policy the caller
/// felt like inventing, and five call paths each inventing one is how the app
/// got here.
abstract class SshTransport {
  /// Cheap, and must not throw: a credential that turns out to be unusable --
  /// a PEM that will not parse, a password the server refuses -- fails at
  /// [SshConnector.connect], which is on the path where this app already shows
  /// failures. Throwing from here instead would take out the screen that was
  /// about to display the reason.
  SshConnector connectorFor(ServerProfile server, SshCredential credential);
}

/// Where the configured servers live between launches.
abstract class ServerStore {
  Future<List<ServerProfile>> load();
  Future<void> save(List<ServerProfile> servers);
}

/// Writes a client bundle somewhere the person can get at it, returning a
/// location to show them.
///
/// Its own port because the packages that do this -- file_selector, share_plus,
/// path_provider -- are not in pubspec.yaml, and this layer does not get to add
/// one.
abstract class FileSaver {
  Future<String> save(String filename, Uint8List bytes);
}

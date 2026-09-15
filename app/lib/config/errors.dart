// Why a share URI could not become a sing-box outbound, said in one located
// sentence.
//
// The failure this replaces is a null dereference three layers down: a URI
// with no `pbk` parsed happily, built a REALITY outbound with no public key,
// and died inside sing-box on somebody's phone with a message nobody could act
// on. Every refusal here names the parameter and what it was for.
//
// No message ever contains a parameter VALUE, and none contains the userinfo.
// The userinfo is a UUID or a password, `obfs-password` is a shared secret, and
// an exception that echoed the URI would put a live credential into a log or a
// crash report. Keys only -- the same stance as `UserSecrets` being its own
// type in control/models.dart.

/// A share URI this app cannot turn into a sing-box outbound.
///
/// Deliberately not a subtype of the control layer's `PayloadException`: that
/// one means "vpnctl answered something unreadable", this one means "the URI
/// inside a perfectly readable answer is not one we can import". A caller that
/// catches them together loses the difference between "update the app" and
/// "this one protocol cannot be used from this device".
final class ShareUriException implements Exception {
  const ShareUriException(this.where, this.reason);

  /// The URI with its credential removed: `vless://…@203.0.113.9:10443`.
  /// Safe to log and safe to put in front of a person.
  final String where;

  /// What was wrong, in the terms of the URI scheme that produced it.
  final String reason;

  String get message => '$where: $reason';

  @override
  String toString() => message;
}

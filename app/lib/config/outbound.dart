// One parsed share URI, as the sing-box outbound it becomes.
//
// Sealed for the same reason `ShareItem` in control/models.dart is: the two
// shapes are not interchangeable, and a switch over them cannot compile while
// ignoring one. VLESS carries the public half of a REALITY key pair, which
// sing-box verifies for real; Hysteria2 carries a certificate fingerprint
// sing-box 1.14 has no field for at all.
//
// Both subtypes live here rather than beside their parsers because `sealed`
// is scoped to the library, not the package -- a subtype in another file
// simply would not compile. The parsers, which are the part that grows when
// the server changes a link, stay in vless_reality.dart and hysteria2.dart.
//
// Every emitted key was checked against sing-box v1.14.0's own documentation;
// the citations are in the report that accompanied this file and the reasons
// for the absences are in the comments below.

/// Where the outbound is referenced from: `route.final`, and the DNS server's
/// `detour`. One constant so the three cannot drift.
const String defaultOutboundTag = 'proxy';

/// An outbound this app can write into a sing-box configuration.
sealed class OutboundConfig {
  const OutboundConfig({
    required this.tag,
    required this.server,
    required this.serverPort,
    required this.profileName,
  });

  final String tag;

  /// The address from the URI's authority: a hostname or a bare IP, never
  /// bracketed. sing-box resolves it with `route.default_domain_resolver`.
  final String server;

  final int serverPort;

  /// The URI's `#fragment`, decoded -- the name the server gave the user.
  ///
  /// Deliberately NOT emitted into the configuration. A sing-box outbound has
  /// a `tag` and no name field, and using the label as the tag would put a
  /// space (or a `#`, or a non-ASCII word) into the string `route.final`
  /// references. It belongs on a list row, not in the config.
  final String? profileName;

  /// The sing-box outbound `type`.
  String get type;

  /// The outbound object, ready for `jsonEncode`.
  Map<String, Object?> toJson();
}

/// A VLESS outbound with REALITY and uTLS, as sing-box 1.14 spells it.
final class VlessRealityOutbound extends OutboundConfig {
  const VlessRealityOutbound({
    required super.tag,
    required super.server,
    required super.serverPort,
    required super.profileName,
    required this.uuid,
    required this.flow,
    required this.serverName,
    required this.fingerprint,
    required this.publicKey,
    required this.shortId,
  });

  /// The user's `vless_uuid`, from the userinfo.
  final String uuid;

  /// `xtls-rprx-vision`.
  final String flow;

  /// `sni` -- the masquerade host REALITY fronts. It is both the TLS SNI and
  /// the name the handshake is proxied to, so it is not cosmetic.
  final String serverName;

  /// The uTLS ClientHello to imitate.
  final String fingerprint;

  /// `pbk`: the X25519 public half, unpadded base64url. The private half never
  /// leaves the server -- see the comment in vless_reality.py's share().
  final String publicKey;

  /// `sid`, hex.
  final String shortId;

  @override
  String get type => 'vless';

  /// `network` and `packet_encoding` are absent on purpose: the link carries
  /// no parameter for either, sing-box's defaults are "both networks" and
  /// "whatever the peer negotiates", and writing a guess here would silence
  /// UDP on a profile whose server permits it.
  @override
  Map<String, Object?> toJson() => <String, Object?>{
        'type': type,
        'tag': tag,
        'server': server,
        'server_port': serverPort,
        'uuid': uuid,
        'flow': flow,
        'tls': <String, Object?>{
          'enabled': true,
          'server_name': serverName,
          'utls': <String, Object?>{
            'enabled': true,
            'fingerprint': fingerprint,
          },
          'reality': <String, Object?>{
            'enabled': true,
            'public_key': publicKey,
            'short_id': shortId,
          },
        },
      };
}

/// How the client is told to trust the Hysteria2 server's certificate.
///
/// Required, with no default, at every call site, because the link's own
/// answer cannot be written down. `pinSHA256` is the SHA-256 of the DER
/// certificate as uppercase colon-separated hex -- what
/// `openssl x509 -fingerprint -sha256` prints and what `cryptography`'s
/// `Certificate.fingerprint()` computes in hysteria2.py's bootstrap(). The
/// nearest key sing-box 1.14 has is `tls.certificate_public_key_sha256`, which
/// is base64 of the SHA-256 of the SubjectPublicKeyInfo: a different preimage
/// and a different encoding, so no re-encoding turns one into the other.
///
/// The certificate is self-signed, so it is in nobody's trust store either.
/// Both answers below are therefore bad, in opposite directions, and choosing
/// between them is not this layer's call to make silently.
enum Hysteria2Trust {
  /// Emit no TLS trust override. sing-box verifies against the system roots,
  /// which this certificate is not in, so the QUIC handshake fails with a
  /// certificate error. Honest, and unusable against this server as it is
  /// configured today.
  systemRoots,

  /// Emit `tls.insecure: true`: accept ANY certificate.
  ///
  /// This is what every other client does with a `pinSHA256` link, and it is
  /// strictly weaker than the pin it replaces -- anything that can get packets
  /// to the client's QUIC session can present its own certificate. The obfs
  /// password and the Hysteria2 password still have to match, so it is not an
  /// open door; it is a downgrade from "this exact certificate" to "this
  /// password over some TLS".
  anyCertificate,
}

/// A Hysteria2 outbound, as sing-box 1.14 spells it.
final class Hysteria2Outbound extends OutboundConfig {
  const Hysteria2Outbound({
    required super.tag,
    required super.server,
    required super.serverPort,
    required super.profileName,
    required this.password,
    required this.serverName,
    required this.trust,
    this.obfsType,
    this.obfsPassword,
    this.pinSha256,
    this.spkiSha256,
  });

  /// The user's `hysteria2_password`, from the userinfo.
  final String password;

  /// `sni`.
  final String serverName;

  final Hysteria2Trust trust;

  /// `salamander`, or null when the link carried no `obfs`.
  final String? obfsType;

  /// Null exactly when [obfsType] is null.
  final String? obfsPassword;

  /// `pinSHA256` as the link spelled it, retained and NOT emitted.
  ///
  /// Kept on the model so a caller can show it, compare it, or hand it to
  /// something that can check it. Dropping it at parse time would hide the
  /// fact that the server asked for a guarantee this config does not give.
  final String? pinSha256;

  /// True when the link pinned a certificate that the emitted configuration
  /// does not check. A UI that connects anyway should say this out loud.
  bool get pinUnenforced => pinSha256 != null;

  /// `spki`: base64(SHA-256(SubjectPublicKeyInfo)), which sing-box CAN check.
  ///
  /// The certificate this server issues is self-signed, so it is in no trust
  /// store and the only way to verify it is to pin it. `pinSHA256` hashes the
  /// whole DER certificate and sing-box has no field for that; this hashes the
  /// public key, which is exactly what `tls.certificate_public_key_sha256`
  /// takes. Optional, because a link issued before the server emitted it has
  /// none, and refusing those would strand every profile already handed out.
  final String? spkiSha256;

  /// True when the emitted configuration accepts ANY server certificate.
  ///
  /// Separate from [pinUnenforced], which only fires when the link carried a
  /// pin. A link with no pin under [Hysteria2Trust.anyCertificate] emits
  /// `tls.insecure` and used to report nothing at all -- the one quadrant the
  /// tests missed, and the dangerous one: anything that can reach the client's
  /// QUIC session gets it, with no warning shown anywhere.
  bool get acceptsAnyCertificate =>
      spkiSha256 == null && trust == Hysteria2Trust.anyCertificate;

  @override
  String get type => 'hysteria2';

  /// `up_mbps`/`down_mbps` are absent on purpose. The link carries no
  /// bandwidth parameters, the server's inbound caps at 100/100 with
  /// `ignore_client_bandwidth: false`, and declaring numbers here would switch
  /// the client from BBR to Hysteria's Brutal congestion control on evidence
  /// that is not in the link.
  @override
  Map<String, Object?> toJson() => <String, Object?>{
        'type': type,
        'tag': tag,
        'server': server,
        'server_port': serverPort,
        'password': password,
        if (obfsType != null)
          'obfs': <String, Object?>{
            'type': obfsType,
            'password': obfsPassword,
          },
        'tls': <String, Object?>{
          'enabled': true,
          'server_name': serverName,
          // Pin the public key when the link carried one: a self-signed
          // certificate is in no trust store, so this is the only check that
          // means anything, and it makes `insecure` unnecessary rather than
          // merely unset.
          if (spkiSha256 != null)
            'certificate_public_key_sha256': <String>[spkiSha256!],
          if (spkiSha256 == null && trust == Hysteria2Trust.anyCertificate)
            'insecure': true,
        },
      };
}

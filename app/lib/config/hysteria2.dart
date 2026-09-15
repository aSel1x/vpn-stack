// hysteria2:// -> [Hysteria2Outbound].
//
// The producer is vpnctl/protocols/hysteria2.py's share():
//
//   hysteria2://<password>@<host>:20443?obfs=salamander
//     &obfs-password=<hex>&sni=<masquerade>&pinSHA256=<AA:BB:...>#<name>
//
// `pinSHA256` cannot be translated. See [Hysteria2Trust] for exactly why, and
// for the choice this parser makes the caller state instead of guessing.

import 'outbound.dart';
import 'share_uri.dart';

const String hysteria2Scheme = 'hysteria2';

const Set<String> _known = <String>{
  'obfs',
  'obfs-password',
  'sni',
  'pinSHA256',
};

/// Parses one `hysteria2://` share link. Pure.
///
/// `obfs`, `obfs-password` and `pinSHA256` are treated as optional even though
/// today's share() always writes all three: they are optional in the scheme,
/// and a parser that requires them would refuse a link from a server whose
/// hysteria2.py stopped obfuscating -- a change that breaks nothing else.
Hysteria2Outbound parseHysteria2Uri(
  String text, {
  required Hysteria2Trust trust,
  String tag = defaultOutboundTag,
}) {
  final ShareUriParts parts = splitShareUri(text, scheme: hysteria2Scheme);
  parts.rejectUnknownParameters(_known);

  final String serverName =
      parts.require('sni', 'which is the name the certificate is issued for');

  final String? obfsType = parts.params['obfs'];
  final String? obfsPassword = parts.params['obfs-password'];
  if (obfsType != null) {
    // sing-box 1.14 also accepts `gecko`, but this server only ever writes
    // salamander, and a link naming anything else did not come from it.
    if (obfsType != 'salamander') {
      parts.refuse(
          'obfs is `$obfsType`, and this server only issues `salamander`');
    }
    if (obfsPassword == null || obfsPassword.isEmpty) {
      // Salamander with no password is not "obfuscation off": sing-box builds
      // the obfuscator anyway and scrambles every packet with a key the server
      // does not share, so the server never sees a handshake at all.
      parts.refuse('obfs is set but obfs-password is not, which would scramble '
          'every packet with a key the server does not share');
    }
  } else if (obfsPassword != null) {
    parts.refuse('obfs-password is set but obfs is not, so there is nothing to '
        'tell sing-box which obfuscator to build');
  }

  return Hysteria2Outbound(
    tag: tag,
    server: parts.host,
    serverPort: parts.port,
    profileName: parts.name,
    password: parts.credential,
    serverName: serverName,
    trust: trust,
    obfsType: obfsType,
    obfsPassword: obfsPassword,
    pinSha256: parts.params['pinSHA256'],
  );
}

// Picking a parser by scheme, and picking a URI out of a share bundle.

import 'errors.dart';
import 'hysteria2.dart';
import 'outbound.dart';
import 'share_uri.dart';
import 'vless_reality.dart';

/// The schemes this app can turn into a sing-box outbound.
///
/// Two, and that is the whole list `vpnctl user export` can produce: ikev2
/// hands out files and dnstt hands out form fields, neither of which is a URI
/// at all -- see the `ShareItem` comment in control/models.dart about what
/// happened the last time settings were crammed into one.
const Set<String> supportedShareSchemes = <String>{
  vlessScheme,
  hysteria2Scheme,
};

/// Parses any supported share URI.
///
/// [hysteria2Trust] has no default and is required even for a `vless://`
/// link, because the caller does not know which scheme it holds until this
/// function has looked. See [Hysteria2Trust]: there is no safe default.
OutboundConfig parseShareUri(
  String text, {
  required Hysteria2Trust hysteria2Trust,
  String tag = defaultOutboundTag,
}) {
  final String scheme = shareUriScheme(text);
  switch (scheme) {
    case vlessScheme:
      return parseVlessRealityUri(text, tag: tag);
    case hysteria2Scheme:
      return parseHysteria2Uri(text, trust: hysteria2Trust, tag: tag);
    default:
      // Named, not ignored. `vmess://`, `ss://` and `trojan://` all look like
      // something this app should handle and are not links this server issues;
      // saying which scheme arrived is what tells somebody they pasted a
      // profile from another panel.
      throw ShareUriException(
        '$scheme://…',
        'this app imports ${supportedShareSchemes.join(' and ')} links, and '
            'those are the only two vpnctl issues',
      );
  }
}

/// The first URI in [uris] that this app can import.
///
/// Order is `ShareBundle.importUris`' order, which is protocol-registry order:
/// VLESS+REALITY before Hysteria2. That is the right preference and not an
/// accident -- REALITY verifies a real handshake against a real site, while
/// Hysteria2's certificate here is self-signed and pinned by a fingerprint
/// sing-box has no field for (see [Hysteria2Trust]).
///
/// Throws when none can be imported, carrying every refusal. A single "no
/// usable profile" would hide the one line that says which parameter was
/// missing.
OutboundConfig selectOutbound(
  List<String> uris, {
  required Hysteria2Trust hysteria2Trust,
  String tag = defaultOutboundTag,
}) {
  if (uris.isEmpty) {
    throw const ShareUriException(
      'the share bundle',
      'has no importable URI at all, so there is nothing to connect with',
    );
  }
  final List<String> refusals = <String>[];
  for (final String uri in uris) {
    try {
      return parseShareUri(uri, hysteria2Trust: hysteria2Trust, tag: tag);
    } on ShareUriException catch (e) {
      refusals.add(e.message);
    }
  }
  throw ShareUriException(
    'the share bundle',
    'none of its ${uris.length} URI(s) could be imported:\n'
        '${refusals.join('\n')}',
  );
}

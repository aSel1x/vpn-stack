import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

import 'ports.dart';

/// Hands one client bundle to the platform's share sheet.
///
/// A share sheet and deliberately not a file picker, because of what these
/// files are. CLAUDE.md records it as verified against the real image: the
/// `.p12` that `ikev2.sh --exportclient` writes has an EMPTY password, so it is
/// an unprotected private key and whoever ends up holding a copy has VPN access
/// as that user, with nothing to type. The sheet is one explicit hand-off to
/// one destination the person picked; a Downloads directory is readable by
/// every app on the phone that asked for storage and by anybody who picks it
/// up. So there is no "save to Downloads" path here and adding one would undo
/// the reason this file exists.
///
/// It is also the only mechanism that reaches the destination that matters. A
/// `.mobileconfig` is an iOS configuration profile, and no API a non-MDM app
/// can call installs one: the route is the sheet, then Files, then tapping it,
/// and Settings takes over. Handing it to the sheet is not a weaker version of
/// installing it -- it is how installing it is done.
class ShareSheetFileSaver implements FileSaver {
  const ShareSheetFileSaver();

  /// Everything this saver has ever written lives under one directory inside
  /// the app's private cache, so the sweep below has one place to look.
  static const String _boxName = 'vpn-stack-bundles';

  @override
  Future<String> save(String filename, Uint8List bytes) async {
    final String name = _safeName(filename);
    final Directory box =
        Directory('${(await getTemporaryDirectory()).path}/$_boxName');

    // Residue, not routine cleanup: the delete below runs on every path out of
    // the share. What a `finally` cannot cover is the app being killed while
    // the sheet is up, and this is what restores the invariant afterwards --
    // one credential in this directory at a time, and never one from a run
    // that is over.
    await _sweep(box);
    await box.create(recursive: true);

    final File file = File('${box.path}/$name');
    try {
      await file.writeAsBytes(bytes, flush: true);
      // A real path, not `XFile.fromData`. That form makes share_plus write its
      // own copy into a UUID subdirectory of the temporary directory and hand
      // back nothing that names it, so nobody can ever delete it: an
      // empty-password `.p12` would accumulate one copy per export with no way
      // to find them. Writing it here is what makes the path knowable.
      final ShareResult result = await SharePlus.instance.share(
        ShareParams(
          files: <XFile>[XFile(file.path, mimeType: _mimeFor(name))],
          // On iPad and Mac the sheet is a popover that wants an anchor rect.
          // There is none to give: `FileSaver` takes a name and bytes, because
          // a port carrying widget geometry would make every non-Apple
          // implementation declare a parameter it ignores. share_plus anchors
          // to the centre of the screen when this is absent rather than
          // throwing, which is the right trade for a port seam.
          subject: name,
        ),
      );
      return _describe(name, result);
    } finally {
      // Always, and immediately: the sheet is finished with this file by the
      // time `share()` completes, on both platforms that matter. On Android the
      // plugin never hands the receiving app this path at all -- it copies the
      // bytes into `cacheDir/share_plus/` and serves the copy through its own
      // FileProvider, so deleting ours races nothing. On iOS and macOS the
      // result comes out of `completionWithItemsHandler`, which fires after the
      // chosen activity has finished with the item.
      //
      // What this cannot delete is that Android copy, which share_plus erases
      // on its own next share. The lifetime of a credential is the whole point
      // of this class, so: `getTemporaryDirectory()` is the app's private cache
      // -- `getCacheDir()` on Android, the container's tmp on iOS -- readable by
      // this app and root and nothing else, and emptied by the OS under disk
      // pressure. That is where the residue sits, not in shared storage.
      await _sweep(box);
    }
  }

  /// Removes everything this saver wrote, ignoring a directory that is not
  /// there.
  Future<void> _sweep(Directory box) async {
    try {
      if (await box.exists()) {
        await box.delete(recursive: true);
      }
    } on FileSystemException {
      // A bundle that could not be deleted is not a reason to refuse the
      // export somebody asked for; it is in private storage either way.
      return;
    }
  }

  String _describe(String name, ShareResult result) {
    switch (result.status) {
      case ShareResultStatus.success:
        return '$name was handed to the share sheet. It is the credential '
            'itself, so wherever it went now grants access as this user.';
      case ShareResultStatus.dismissed:
        return 'The share sheet was dismissed, so $name went nowhere and the '
            'copy this app made has been deleted.';
      case ShareResultStatus.unavailable:
        // share_plus's own sentinel for a platform that does not report what
        // the person chose. Saying "shared" here would claim a delivery this
        // app did not observe, and these three files are worth knowing the
        // whereabouts of.
        return '$name was handed to the platform, which does not report what '
            'happened to it. Check that it arrived before relying on it.';
    }
  }

  /// The server names these files, and a name is not a path.
  ///
  /// `--exportclient` produces `<user>.p12` and `user add` already validates
  /// the name against `[A-Za-z0-9._-]`, so in practice this never fires. It is
  /// here because the check belongs on this side too: this app writes the file,
  /// a separator or a `..` in the name would put it somewhere else on the
  /// device, and "the server would not do that" is an assumption about a
  /// machine somebody else may be operating.
  static String _safeName(String filename) {
    final String trimmed = filename.trim();
    if (trimmed.isEmpty ||
        trimmed == '.' ||
        trimmed == '..' ||
        trimmed.contains('/') ||
        trimmed.contains(r'\')) {
      throw FormatException(
        'the server called this bundle "$filename", which is not a plain file '
        'name. It is not being written: a name carrying a path separator '
        'chooses where on this device the file lands.',
      );
    }
    return trimmed;
  }

  /// What the receiving app is told it is getting.
  ///
  /// Android's chooser filters on the MIME type, so this decides whether
  /// strongSwan is even offered; iOS derives its own UTI from the extension and
  /// barely consults it. A table rather than the `mime` package's lookup
  /// because that returns null for all three of these extensions, and
  /// share_plus's fallback is `application/octet-stream` -- which is right for
  /// the one nothing has registered and wrong for the two that have.
  static String _mimeFor(String name) {
    final String lower = name.toLowerCase();
    if (lower.endsWith('.p12')) {
      return 'application/x-pkcs12';
    }
    if (lower.endsWith('.mobileconfig')) {
      // The type Apple registers for a configuration profile. Not guessable,
      // and it is what makes iOS offer to install rather than to store.
      return 'application/x-apple-aspen-config';
    }
    // `.sswan` is strongSwan's own JSON profile and nothing registers a type
    // for it; the app that reads it matches the extension.
    return 'application/octet-stream';
  }
}

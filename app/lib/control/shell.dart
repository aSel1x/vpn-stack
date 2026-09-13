// Turning an argument vector back into the one string SSH can carry.
//
// This is the only place in the app allowed to build a shell command, and it
// exists because `./vpn` once did not have it: `$*` unquoted is re-split by the
// remote shell, so a user name with a space arrived as two arguments and, one
// layer down, misaligned the space-separated IKEv2 user and password lists.
// `printf '%q'` is the bash version of this function.

/// Characters that cannot change meaning to any POSIX shell, so they need no
/// quoting. Deliberately conservative: everything else gets quoted, including
/// the empty string, `~` and `*`.
final RegExp _bare = RegExp(r'^[A-Za-z0-9_@%+=:,./-]+$');

/// Single-quotes [word] unless it is provably inert.
String shellQuote(String word) {
  if (_bare.hasMatch(word)) {
    return word;
  }
  // Close the quote, emit an escaped quote, reopen: the only way to get a
  // single quote through a single-quoted string.
  return "'${word.replaceAll("'", r"'\''")}'";
}

/// Quotes every element of [argv] and joins them with spaces.
///
/// The result is what an `exec` channel should be handed. A leading `-` is left
/// alone on purpose: it is safe for the shell, and what to do about an argument
/// the *remote program* would read as an option is the caller's decision, not
/// the quoter's.
String shellCommand(List<String> argv) => argv.map(shellQuote).join(' ');

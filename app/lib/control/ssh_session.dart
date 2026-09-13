// The transport, as a hole in this layer rather than a dependency of it.
//
// Nothing under control/ imports dartssh2. The session is injected, which is
// what makes every command line and every parse in here testable with no
// server, no key and no network -- and it keeps the choice of SSH library one
// small file to replace rather than a rewrite.

/// What one remote command produced.
class CommandResult {
  const CommandResult({
    required this.exitCode,
    required this.stdout,
    required this.stderr,
  });

  /// The remote program's exit status. vpnctl's own `die()` exits 1 with a JSON
  /// body; argparse exits 2 with a usage message on stderr and no JSON at all;
  /// 127 is a shell that could not find vpnctl. The three are different
  /// failures and the caller is entitled to tell them apart.
  final int exitCode;

  /// stdout, which under `--json` carries the payload and nothing else:
  /// vpnctl's `say()` is silent in JSON mode and `warn()` writes to stderr.
  final String stdout;

  /// stderr: warnings, notes, and anything the remote shell had to say.
  /// Never parsed as payload.
  final String stderr;
}

/// Runs one command on the server and waits for it.
abstract class SshSession {
  /// Runs [argv] to completion.
  ///
  /// [argv] is an argument vector, not a command line: element 0 is the
  /// program, and no element may be re-split, globbed or variable-expanded on
  /// the far side. SSH only ever carries a single command *string*, so an
  /// implementation has to quote every element -- `shellCommand` in shell.dart
  /// does that, and is the only place it has to be right. `./vpn` shipped the
  /// unquoted version of this and one argument containing a space silently
  /// became two.
  ///
  /// Throws whatever the transport throws; [Vpnctl] catches it and reports a
  /// transport failure, because a command that never produced an exit status
  /// tells you nothing about whether it ran.
  Future<CommandResult> run(List<String> argv);
}

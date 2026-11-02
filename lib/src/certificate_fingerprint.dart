import 'dart:io';

import 'package:crypto/crypto.dart';

/// Opens a TLS connection to [uri] and checks whether the SHA-256
/// fingerprint of the server's leaf certificate is in [allowedFingerprints].
Future<bool> isCertificateAllowed(
  Uri uri,
  List<String> allowedFingerprints, {
  Duration timeout = const Duration(seconds: 10),
}) async {
  final socket = await SecureSocket.connect(
    uri.host,
    uri.hasPort ? uri.port : 443,
    timeout: timeout,
  );
  try {
    final cert = socket.peerCertificate;
    if (cert == null) return false;
    return fingerprintMatches(cert.der, allowedFingerprints);
  } finally {
    socket.destroy();
  }
}

/// Returns whether the SHA-256 hash of [der] matches one of
/// [allowedFingerprints].
///
/// Fingerprints are compared case-insensitively; whitespace and `:`
/// separators are ignored.
bool fingerprintMatches(List<int> der, List<String> allowedFingerprints) {
  final hash = sha256.convert(der).toString().toUpperCase();
  return allowedFingerprints
      .map((fp) => fp.toUpperCase().replaceAll(RegExp(r'[\s:]'), ''))
      .contains(hash);
}

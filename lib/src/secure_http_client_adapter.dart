import 'dart:io';
import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';
import 'package:dio/io.dart';
import 'package:flutter/foundation.dart';

import 'flutter_secure_app.dart';

/// Güvenlik Katmanı: Anti-Proxy (Sniffing engelleme) ve SPKI pinning.
class SecureHttpClientAdapter {
  static IOHttpClientAdapter getAdapter({
    List<String>? allowedSpkiHashes,
    bool bypassSpkiForLocalhost = true,
  }) {
    final adapter = IOHttpClientAdapter();

    adapter.createHttpClient = () {
      final client = HttpClient()
        ..findProxy = (uri) {
          return 'DIRECT'; // Bypass proxy parameters
        };
      return client;
    };

    if (allowedSpkiHashes != null && allowedSpkiHashes.isNotEmpty) {
      adapter.validateCertificate =
          (X509Certificate? cert, String host, int port) {
        
        if (bypassSpkiForLocalhost && _isLocalhost(host)) {
          return true;
        }

        if (cert == null) return false;

        final isSecure = _verifySpkiPinning(cert, allowedSpkiHashes);

        if (!isSecure) {
          _handleSslThreat();
        }

        return isSecure;
      };
    }

    return adapter;
  }

  static bool _isLocalhost(String host) {
    return host == 'localhost' || host == '127.0.0.1' || host == '10.0.2.2';
  }

  static bool _verifySpkiPinning(
      X509Certificate cert, List<String> allowedHashes) {
    try {
      final spkiBytes = _extractSpkiWithParser(cert.der);
      final computedHash = sha256.convert(spkiBytes).toString().toUpperCase();
      final normalizedComputedHash = _normalizeHexString(computedHash);

      final allowedNormalizedHashes = allowedHashes
          .map((hash) => _normalizeHexString(hash))
          .where((hash) => hash.isNotEmpty)
          .toSet();

      return allowedNormalizedHashes.contains(normalizedComputedHash);
    } catch (e) {
      debugPrint('SPKI pinning verification error: $e');
      return false;
    }
  }

  static Uint8List _extractSpkiWithParser(Uint8List der) {
    final parser = ASN1Parser(der);
    final topLevelSeq = parser.nextObject() as ASN1Sequence;
    final tbsCertificate = topLevelSeq.elements[0] as ASN1Sequence;

    for (final element in tbsCertificate.elements) {
      if (element is ASN1Sequence &&
          element.elements.isNotEmpty &&
          element.elements[0] is ASN1Sequence) {
        return element.encodedBytes;
      }
    }

    throw Exception('SubjectPublicKeyInfo block not found in certificate');
  }

  static void _handleSslThreat() {
    FlutterSecureApp().notifySslPinningError();
  }

  static String _normalizeHexString(String value) {
    return value.toUpperCase().replaceAll(RegExp(r'[^A-F0-9]'), '');
  }
}

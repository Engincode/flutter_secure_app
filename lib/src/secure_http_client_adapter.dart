import 'dart:io';
import 'package:dio/io.dart';

/// Güvenlik Katmanı: Anti-Proxy (Sniffing engelleme)
class SecureHttpClientAdapter {
  static IOHttpClientAdapter getAdapter() {
    return IOHttpClientAdapter(
      createHttpClient: () {
        final client = HttpClient()
          ..findProxy = (uri) {
            return 'DIRECT'; // Bypass proxy parameters
          };
        return client;
      },
    );
  }
}

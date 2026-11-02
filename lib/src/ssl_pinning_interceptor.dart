import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import 'certificate_fingerprint.dart';
import 'flutter_secure_app.dart';

/// SSL Pinning Interceptor
class SslPinningInterceptor extends Interceptor {
  final List<String> allowedFingerprints;
  final bool bypassForLocalhost;

  SslPinningInterceptor({
    required this.allowedFingerprints,
    this.bypassForLocalhost = true,
  });

  @override
  Future<void> onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    if (bypassForLocalhost && kDebugMode) {
      if (options.baseUrl.contains('localhost') ||
          options.baseUrl.contains('10.0.2.2') ||
          options.baseUrl.contains('127.0.0.1')) {
        return handler.next(options);
      }
    }

    try {
      final secure = await isCertificateAllowed(
        options.baseUrl.isNotEmpty ? Uri.parse(options.baseUrl) : options.uri,
        allowedFingerprints,
      );

      if (secure) {
        return handler.next(options);
      } else {
        return _handleSslPinningError(options, handler);
      }
    } on HandshakeException catch (_) {
      // The certificate chain is not trusted by the system.
      return _handleSslPinningError(options, handler);
    } on TimeoutException catch (_) {
      return handler.reject(
        DioException(
          requestOptions: options,
          error: 'Connection Timeout',
          type: DioExceptionType.connectionTimeout,
        ),
      );
    } on SocketException catch (_) {
      return handler.reject(
        DioException(
          requestOptions: options,
          error: 'Socket Exception',
          type: DioExceptionType.connectionError,
        ),
      );
    } catch (e) {
      return handler.reject(
        DioException(requestOptions: options, error: 'Unknown Error: $e'),
      );
    }
  }

  void _handleSslPinningError(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) {
    FlutterSecureApp().notifySslPinningError();
    return handler.reject(
      DioException(
        requestOptions: options,
        error: 'SSL Pinning Error: Certificate mismatch!',
        type: DioExceptionType.connectionError,
      ),
    );
  }
}

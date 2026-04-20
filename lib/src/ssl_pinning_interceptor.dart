import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:http_certificate_pinning/http_certificate_pinning.dart';

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
      final secure = await HttpCertificatePinning.check(
        serverURL: options.baseUrl,
        headerHttp: Map<String, String>.from(options.headers),
        sha: SHA.SHA256,
        allowedSHAFingerprints: allowedFingerprints,
        timeout: 10,
      );

      if (secure.contains('CONNECTION_SECURE')) {
        return handler.next(options);
      } else {
        return _handleSslPinningError(options, handler);
      }
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
      if (e.toString().contains('CONNECTION_NOT_SECURE')) {
        return _handleSslPinningError(options, handler);
      } else {
        return handler.reject(
          DioException(
            requestOptions: options,
            error: 'Unknown Error: $e'
          ),
        );
      }
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

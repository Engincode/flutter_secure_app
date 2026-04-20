import 'package:flutter/material.dart';
import 'dart:async';

import 'package:flutter_secure_app/flutter_secure_app.dart';
import 'package:dio/dio.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _threatStatus = 'Checking...';
  List<String> _detectedThreats = [];

  @override
  void initState() {
    super.initState();
    initPlatformState();
  }

  Future<void> initPlatformState() async {
    // 1. Initialize RASP engine
    await FlutterSecureApp().init(
      isProdEnv: true,
      onThreatDetected: (threatType) {
        setState(() {
          _detectedThreats.add(threatType.toString());
        });
        print('THREAT DETECTED: $threatType');
        // Handle threat here (e.g. exit app, show warning)
      },
    );

    // 2. Setup Dio with Anti-Proxy and SSL Pinning
    final dio = Dio(BaseOptions(baseUrl: 'https://reqres.in'));
    dio.httpClientAdapter = SecureHttpClientAdapter.getAdapter();
    dio.interceptors.add(
      SslPinningInterceptor(
        allowedFingerprints: [
          // Example fingerprint
          '5A:C3:A8:D5:11:47:A5:72:0B:44:83:8B:D8:1A:30:A5:68:55:A6:DB:99:7E:59:75:A8:F5:F2:B5:12:F1:C9:92',
        ],
        bypassForLocalhost: true,
      ),
    );

    setState(() {
      if (FlutterSecureApp().isSafe) {
        _threatStatus = 'Device is Safe';
      } else {
        _threatStatus = 'Device is NOT Safe';
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('Flutter Secure App Example')),
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(
                'Security Status: $_threatStatus',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 20),
              if (_detectedThreats.isNotEmpty)
                Text(
                  'Detected Threats:\n${_detectedThreats.join('\n')}',
                  style: const TextStyle(
                    color: Colors.red,
                    fontWeight: FontWeight.bold,
                  ),
                  textAlign: TextAlign.center,
                ),
            ],
          ),
        ),
      ),
    );
  }
}

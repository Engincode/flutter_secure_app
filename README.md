# Flutter Secure App

A comprehensive RASP (Runtime Application Self-Protection) and Anti-Tampering Flutter plugin natively bridging security rules for Android & iOS to the Dart layer. Ensure reverse-engineers, malware, and interceptors have a difficult time compromising your app's environment.

## Features

- **Jailbreak / Root Detection:** Detects compromised devices iOS Jailbreak and Android Rooting.
- **Simulator / Emulator Detection:** Prevents your app from running on fraudulent emulator environments.
- **Debugger Access Detection:** Halts app execution if a debugger is attached.
- **App Signature Checks & Signature Validations:** Validates Android Signatures and iOS Apple Team IDs to prevent app repackaging and tampering.
- **Store Verification (Vending):** Checks if the app was downloaded from official stores (App Store / Google Play).
- **Device Binding & ID Spoofing Protections:** Prevents device identifiers from being spoofed.
- **Advanced String Obfuscation:** Protects sensitive identifiers (like Signatures or Team IDs) against static analysis by decoding them via XOR at runtime.

## Installation

Add this to your `pubspec.yaml`:

```yaml
dependencies:
  flutter_secure_app: ^1.0.0
```

## Getting Started & Usage

Just import and initialize the plugin at the root of your application (preferably before starting the app logic):

```dart
import 'package:flutter_secure_app/flutter_secure_app.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  await FlutterSecureApp().init(
    isEnabled: true,
    isProdEnv: true, // Toggles specific logic like Store Verification check

    // Granular Threat Toggles (Disable during development):
    checkJailbreakOrHooking: !kDebugMode,
    checkEmulator: !kDebugMode,
    checkDebugger: !kDebugMode,
    checkAppSignature: !kDebugMode,
    checkOfficialStore: !kDebugMode,
    checkDeviceBinding: !kDebugMode,
    checkDeviceIdSpoofing: !kDebugMode,

    // XOR Obfuscator (String Hiding) - Reverse Engineering Protection:
    // Pass your plain or decoded signatures arrays dynamically.
    validIosTeamIds: [
      // e.g., '1234567890' or dynamic decoded strings
      MyGlobalSecureConfig.appleTeamId,
    ],
    validAndroidSignatures: [
      // e.g., 'A1:B2:C3...'
      MyGlobalSecureConfig.androidSignature,
    ],
    // Optional: If you pass Base64+XOR strings above, set this key so the plugin decodes them silently in memory:
    // obfuscationXorKey: 'my_plugin_level_xor_key_here',

    onThreatDetected: (SecureAppThreatType threatType) {
      print('A security threat occurred: $threatType');
      // For example, terminate app gracefully or block login.
    },
    onException: (error, stackTrace) {
      print('Plugin internals threw an error: $error');
    }
  );

  runApp(MyApp());
}
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `isEnabled` | `bool` | `true` | Completely enables or disables the plugin engine. |
| `isProdEnv` | `bool` | `true` | Used to enforce production-only checks such as Official Store vending checks. |
| `checkJailbreakOrHooking` | `bool` | `true` | Validates if device is rooted/jailbroken or has hooking frameworks. |
| `checkEmulator` | `bool` | `true` | Validates if device is an emulator. |
| `checkDebugger` | `bool` | `true` | Validates if a debugger is attached. |
| `checkAppSignature` | `bool` | `true` | Checks if the app is repackaged or signed by unauthorized certificates. |
| `checkOfficialStore` | `bool` | `true` | Verifies installation source is App Store/Google Play (Ignored if `isProdEnv` is `false`). |
| `validIosTeamIds` | `List<String>` | `[]` | List of approved Apple Team IDs. |
| `validAndroidSignatures` | `List<String>` | `[]` | List of approved Android App Signatures. |
| `obfuscationXorKey` | `String?` | `null` | Key for internal Base64/XOR decoding. Ignore if sending pre-decoded values. |
| `onThreatDetected` | `Function` | `null` | Callback triggered when a threat is identified. |
| `onException` | `Function` | `null` | Callback for internal plugin exceptions/errors. |

### Network Security (Dio Integration)

The plugin provides ready-to-use tools for the popular `dio` package to secure your network layer against Man-in-the-Middle (MITM) attacks and malicious proxy sniffing.

**1. SSL Pinning Interceptor**  
Validates the server certificate SHA-256 fingerprints. If the hash doesn't match, the request is rejected and `SecureAppThreatType.sslPinningError` is triggered.

**2. Secure HTTP Client Adapter (Anti-Proxy)**  
Forces the HTTP client to bypass system proxy configurations, making it extremely difficult to intercept traffic using tools like Charles Proxy or Burp Suite.

```dart
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_app/flutter_secure_app.dart';

final dio = Dio();

// 1. Add SSL Pinning Interceptor
dio.interceptors.add(SslPinningInterceptor(
  allowedFingerprints: [
    'YOUR_SERVER_SHA256_FINGERPRINT_1',
    'YOUR_SERVER_SHA256_FINGERPRINT_2',
  ],
  bypassForLocalhost: kDebugMode, // Bypass pinning for local API testing
));

// 2. Set Secure HTTP Adapter (Anti-Proxy)
dio.httpClientAdapter = SecureHttpClientAdapter.getAdapter();
```

### How String Obfuscation Works

Storing your `Apple TeamID` and `Android Signatures` in plain-text inside Dart makes it extremely easy for reverse-engineers to bypass signature checks by searching for those strings. 

**Option 1 (External Decrypt):** You can use your own custom Integer XOR arrays to decode your signatures precisely at runtime and pass the clean string to `validIosTeamIds` and `validAndroidSignatures`. The plugin handles them directly in memory.

**Option 2 (Built-in Plugin Decrypt):** 
1. Obfuscate your string with a XOR Key + Base64 format offline.
2. Put the encoded string into `validAndroidSignatures`  and pass your `obfuscationXorKey`.
3. The plugin will natively decode the Base64/XOR string into memory securely avoiding plain-text exposure in your APK/IPA.

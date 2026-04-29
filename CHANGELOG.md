## 1.0.5

* Release `1.0.5` to publish latest Flutter/Dart upgrade and SPKI pinning documentation updates.

## 1.0.4

* Bumped version for new package release.
* Confirmed Flutter/Dart support upgrade and highlighted `SSL SPKI Pinning Interceptor` feature.

## 1.0.3

* Updated README to highlight `SSL SPKI Pinning Interceptor` as a separate feature.
* Clarified SPKI pinning support and example usage for `SecureHttpClientAdapter`.

## 1.0.2

* SSL SPKI Pinning Interceptor Added (SSL Subject Public Key Info Control)
* Added optional SPKI pinning support to `SecureHttpClientAdapter` for public key validation.
* Kept existing SHA-256 certificate fingerprint pinning flow in `SslPinningInterceptor`.
* Added `asn1lib` and `crypto` dependencies to support SPKI extraction and hashing.
* Updated README and example usage for SPKI pinning integration.

## 1.0.1

* Updated README with detailed network security (Dio) features and pub.dev badges.

## 1.0.0

* Initial release.
* Integrated RASP features: Jailbreak/Root, Emulator, and Debugger detection.
* Integrated App Signature and iOS Team ID validation.
* Added SSL Pinning and SecureHttpClientAdapter for secure Dio requests.

# iOS app

This folder contains a SwiftUI app that calls the Rust client benchmark flow through a C ABI FFI.

## Build the FFI framework

1. Install the iOS Rust targets (once):

   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

2. Build the xcframework:

   ./ios/build-ffi.sh

This writes `ios/OoniAuthBindings/OoniAuthFFI.xcframework`.

## Run the app

Open `ios/OoniAuthApp.xcodeproj` in Xcode and run the `OoniAuthApp` target.
The app has a single button that executes the Rust `ooniauth_run_client_benchmarks` flow via FFI. The results display the mean and standard deviation in milli-seconds for each client protocol.

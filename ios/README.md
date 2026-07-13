# iOS app

This folder contains a SwiftUI app that calls the Rust demo flow through a C ABI FFI.

## Prerequisites

1. Install Xcode from the App Store, launch it once, accept the license, and install the iOS platform when prompted (this includes the simulator).
2. Install Rust via [rustup](https://rustup.rs).

## Build the FFI framework

1. Install the iOS Rust targets (once):

   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

2. Build the xcframework:

   ./ios/build-ffi.sh

This writes `ios/OoniAuthBindings/OoniAuthFFI.xcframework`.

## Run the app

Open `ios/OoniAuthApp.xcodeproj` in Xcode and run the `OoniAuthApp` target.
The app has a single "Run Demo" button that executes the Rust `basic_usage` flow via FFI.

## Troubleshooting

If the build fails with `xcodebuild ... requires Xcode` or a missing iOS SDK:

    sudo xcode-select -s /Applications/Xcode.app/Contents/Developer

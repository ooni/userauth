import SwiftUI

struct ContentView: View {
    @State private var log = "Tap Run Demo to execute the Rust flow via FFI."
    @State private var isRunning = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("OONI Auth Benchmarks")
                .font(.title2)
                .fontWeight(.semibold)

            Text("Runs the client benchmark flow from Rust and prints the compact table below.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Button(action: runBenchmarks) {
                HStack {
                    if isRunning {
                        ProgressView()
                    }
                    Text(isRunning ? "Running..." : "Run Benchmarks")
                }
            }
            .disabled(isRunning)

            Divider()

            ScrollView {
                Text(log)
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(.vertical, 4)
            }
        }
        .padding()
    }

    private func runBenchmarks() {
        isRunning = true
        log = "Running..."

        DispatchQueue.global(qos: .userInitiated).async {
            let output = OoniAuthFFI.runClientBenchmarks()
            DispatchQueue.main.async {
                log = output
                isRunning = false
            }
        }
    }
}

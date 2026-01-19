import SwiftUI

struct ContentView: View {
    @State private var log = "Tap Run Demo to execute the Rust flow via FFI."
    @State private var isRunning = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("OONI Auth Demo")
                .font(.title2)
                .fontWeight(.semibold)

            Text("Runs the basic_usage flow from Rust and prints the result below.")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Button(action: runDemo) {
                HStack {
                    if isRunning {
                        ProgressView()
                    }
                    Text(isRunning ? "Running..." : "Run Demo")
                }
            }
            .disabled(isRunning)

            Divider()

            ScrollView {
                Text(log)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(.vertical, 4)
            }
        }
        .padding()
    }

    private func runDemo() {
        isRunning = true
        log = "Running..."

        DispatchQueue.global(qos: .userInitiated).async {
            let output = OoniAuthFFI.runBasicUsage()
            DispatchQueue.main.async {
                log = output
                isRunning = false
            }
        }
    }
}

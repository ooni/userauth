import Foundation

@_silgen_name("ooniauth_run_client_benchmarks")
private func ooniauth_run_client_benchmarks() -> UnsafeMutablePointer<CChar>?

@_silgen_name("ooniauth_string_free")
private func ooniauth_string_free(_ ptr: UnsafeMutablePointer<CChar>?)

enum OoniAuthFFI {
    static func runClientBenchmarks() -> String {
        guard let raw = ooniauth_run_client_benchmarks() else {
            return "error: FFI returned null pointer"
        }
        defer { ooniauth_string_free(raw) }
        return String(cString: raw)
    }
}

import Foundation
import GatePassProtocol
import GatePassService
import Vapor

@main
struct Server {
  static func main() async throws {
    var environment = try Environment.detect()
    try LoggingSystem.bootstrap(from: &environment)
    let app = try await Application.make(environment)
    do {
      let state = URL(
        fileURLWithPath: ProcessInfo.processInfo.environment["GATEPASS_STATE_DIR"] ?? ".gatepass",
        isDirectory: true)
      let tokenFile = URL(
        fileURLWithPath: ProcessInfo.processInfo.environment["GATEPASS_OWNER_TOKEN_FILE"]
          ?? state.appendingPathComponent("owner.token").path)
      if !FileManager.default.fileExists(atPath: tokenFile.path) {
        try PrivateFile.write(Data(GatePassCrypto.randomToken().utf8), to: tokenFile)
      }
      let token = try String(contentsOf: tokenFile, encoding: .utf8).trimmingCharacters(
        in: .whitespacesAndNewlines)
      guard GatePassCrypto.decodeToken(token) != nil else {
        throw GatePassError("Owner token file must contain one GatePass token")
      }
      try await GatePassService.configure(
        app,
        databaseURL: ProcessInfo.processInfo.environment["DATABASE_URL"]
          ?? "postgres://gatepass@127.0.0.1:5433/gatepass?sslmode=disable",
        ownerHash: GatePassCrypto.hash(token))
      try await app.execute()
      try await app.asyncShutdown()
    } catch {
      try? await app.asyncShutdown()
      throw error
    }
  }
}

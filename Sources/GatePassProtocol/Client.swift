import Foundation

public struct GatePassHTTPError: Error, LocalizedError, Sendable {
  public let status: Int
  public let reason: String
  public var errorDescription: String? { "HTTP \(status): \(reason)" }
}

private final class RejectRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
  func urlSession(
    _ session: URLSession, task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
    completionHandler: @escaping @Sendable (URLRequest?) -> Void
  ) { completionHandler(nil) }
}

public struct GatePassClient: Sendable {
  public let origin: URL
  public let token: String
  public let session: URLSession
  public init(server: String, token: String, session: URLSession? = nil) throws {
    guard let url = URL(string: server), url.user == nil, url.password == nil, url.query == nil,
      url.fragment == nil,
      let host = url.host, url.path.isEmpty || url.path == "/",
      url.scheme == "https"
        || (url.scheme == "http" && ["127.0.0.1", "localhost", "[::1]", "::1"].contains(host))
    else { throw GatePassError("Use an HTTPS origin, or HTTP on loopback for local development") }
    self.origin = url
    self.token = token
    self.session =
      session
      ?? URLSession(configuration: .ephemeral, delegate: RejectRedirects(), delegateQueue: nil)
  }
  public func request(_ method: String, _ path: String, body: JSONObject? = nil) async throws -> (
    JSONObject, Bool
  ) {
    guard path.hasPrefix("/v1/") else { throw GatePassError("Invalid API path") }
    var request = URLRequest(url: URL(string: path, relativeTo: origin)!.absoluteURL)
    request.httpMethod = method
    request.timeoutInterval = 15
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    if let body { request.httpBody = try GatePassCrypto.canonical(body) }
    let (bytes, rawResponse) = try await session.bytes(for: request)
    guard let response = rawResponse as? HTTPURLResponse else {
      bytes.task.cancel()
      throw GatePassError("Invalid server response")
    }
    guard !(300..<400).contains(response.statusCode) else {
      bytes.task.cancel()
      throw GatePassError("Server redirects are not allowed")
    }
    let limit = 4 * 1024 * 1024
    guard response.expectedContentLength <= Int64(limit) else {
      bytes.task.cancel()
      throw GatePassError("Server response exceeds limit")
    }
    var data = Data()
    for try await byte in bytes {
      guard data.count < limit else {
        bytes.task.cancel()
        throw GatePassError("Server response exceeds limit")
      }
      data.append(byte)
    }
    let decoded = try? JSONDecoder().decode(JSONObject.self, from: data)
    guard (200..<300).contains(response.statusCode) else {
      throw GatePassHTTPError(
        status: response.statusCode, reason: decoded?["reason"]?.string ?? "Request rejected")
    }
    guard let decoded else { throw GatePassError("Server returned malformed JSON") }
    return (decoded, response.value(forHTTPHeaderField: "GatePass-Replayed") == "true")
  }
}

public struct ScannerSetup: Codable, Sendable {
  public let server: String
  public let eventID: String
  public let deviceID: String
  public let label: String
  public let credential: String
  public let expiresAt: String
  public init(
    server: String, eventID: String, deviceID: String, label: String, credential: String,
    expiresAt: String
  ) {
    self.server = server
    self.eventID = eventID
    self.deviceID = deviceID
    self.label = label
    self.credential = credential
    self.expiresAt = expiresAt
  }
}

public struct ScanOutbox: Codable, Sendable {
  public let operationID: String
  public let eventID: String
  public let deviceID: String
  public var request: JSONObject?
  public var response: JSONObject?
  public var acknowledged: Bool
  public init(operationID: String, eventID: String, deviceID: String, request: JSONObject) {
    self.operationID = operationID
    self.eventID = eventID
    self.deviceID = deviceID
    self.request = request
    self.response = nil
    self.acknowledged = false
  }
  private func validate(_ value: JSONObject) throws {
    guard value["operation_id"]?.string == operationID,
      value["event_id"]?.string == eventID,
      let decision = value["decision"]?.string,
      ["accepted", "already_admitted", "revoked", "invalid_ticket", "event_closed", "wrong_event"]
        .contains(decision)
    else {
      throw GatePassError("Unrecognized or mismatched admission response")
    }
    if ["accepted", "already_admitted", "revoked"].contains(decision) {
      guard let ticket = value["ticket_id"]?.string, UUID(uuidString: ticket) != nil,
        let name = value["display_name"]?.string, !name.isEmpty
      else { throw GatePassError("Incomplete admission response") }
    }
    if ["accepted", "already_admitted"].contains(decision) {
      guard let time = value["admitted_at"]?.string, ISO8601DateFormatter().date(from: time) != nil,
        let staff = value["admitted_by"]?.string, !staff.isEmpty
      else { throw GatePassError("Incomplete admission metadata") }
    }
  }
  public mutating func resolve(with client: GatePassClient, file: URL) async throws -> (
    JSONObject, Bool
  ) {
    if let response {
      try validate(response)
      return (response, true)
    }
    guard let request else { throw GatePassError("Outbox lacks pending request") }
    let result: (JSONObject, Bool)
    do {
      result = try await client.request(
        "GET", "/v1/events/\(eventID)/devices/me/scans/\(operationID)")
    } catch let error as GatePassHTTPError where error.status == 404 {
      let kind = request["ticket_id"] == nil ? "scans" : "manual-scans"
      result = try await client.request("POST", "/v1/events/\(eventID)/\(kind)", body: request)
    }
    try validate(result.0)
    var committed = self
    committed.response = result.0
    committed.request = nil
    try PrivateFile.write(GatePassCrypto.canonical(committed), to: file)
    self = committed
    return result
  }
}

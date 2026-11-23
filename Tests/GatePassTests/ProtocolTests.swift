import Foundation
import Testing

@testable import GatePassProtocol

@Test func rosterPreservesIdentifiersAndQuotedFields() throws {
  let input =
    "\u{feff}external_id,display_name,email\r\n00017,\"Lee, Morgan\",lee@example.test\r\n00018,\"Multi\nLine\",\r\n"
  let entries = try RosterCSV.parse(Data(input.utf8))
  #expect(entries.count == 2)
  #expect(entries[0].externalID == "00017")
  #expect(entries[0].displayName == "Lee, Morgan")
  #expect(entries[1].displayName == "Multi\nLine")
}
@Test func rosterRejectsDuplicateAndMalformedInput() {
  #expect(throws: (any Error).self) {
    try RosterCSV.parse(Data("external_id,display_name\n1,A\n1,B".utf8))
  }
  #expect(throws: (any Error).self) {
    try RosterCSV.parse(Data("external_id,display_name\n1,\"A".utf8))
  }
  #expect(throws: (any Error).self) {
    try RosterCSV.parse(Data("external_id,display_name\n1,\"A\"oops".utf8))
  }
}
@Test func ticketCodesAreStrictAndRoundTrip() throws {
  let event = UUID().uuidString
  let token = GatePassCrypto.randomToken()
  let code = try TicketCode(eventID: event, secret: token)
  #expect(try TicketCode(code.rawValue) == code)
  #expect(throws: (any Error).self) { try TicketCode("https://untrusted.example/ticket") }
  #expect(throws: (any Error).self) { try TicketCode(eventID: event, secret: "short") }
}
@Test func archiveRejectsTamperingAndWrongKeys() throws {
  let key = GatePassCrypto.decodeToken(GatePassCrypto.randomToken())!
  let other = GatePassCrypto.decodeToken(GatePassCrypto.randomToken())!
  let data = Data("secret tickets".utf8)
  let sealed = try GatePassCrypto.seal(data, key: key)
  #expect(try GatePassCrypto.open(sealed, key: key) == data)
  #expect(throws: (any Error).self) { try GatePassCrypto.open(sealed, key: other) }
  var changed = sealed
  changed[changed.count - 1] ^= 1
  #expect(throws: (any Error).self) { try GatePassCrypto.open(changed, key: key) }
}
@Test func exportNeutralizesSpreadsheetFormulaCells() {
  #expect(RosterCSV.encodeCell("=1+1") == "\"'=1+1\"")
  #expect(RosterCSV.encodeCell("00017") == "\"00017\"")
  #expect(RosterCSV.encodeCell("Lee, Morgan") == "\"Lee, Morgan\"")
}
@Test func remoteHTTPOriginsAreRejected() {
  #expect(throws: (any Error).self) {
    try GatePassClient(server: "http://192.168.1.12:8788", token: "test")
  }
  #expect(throws: (any Error).self) {
    try GatePassClient(server: "https://user:secret@example.com", token: "test")
  }
}

private final class AcceptedResponseProtocol: URLProtocol, @unchecked Sendable {
  override class func canInit(with request: URLRequest) -> Bool { true }
  override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
  override func startLoading() {
    let response = HTTPURLResponse(
      url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1",
      headerFields: ["Content-Type": "application/json"])!
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    client?.urlProtocol(
      self,
      didLoad: Data(
        "{\"decision\":\"invalid_ticket\",\"operation_id\":\"fixture\",\"event_id\":\"event\"}".utf8
      ))
    client?.urlProtocolDidFinishLoading(self)
  }
  override func stopLoading() {}
}

@Test func outboxRetainsPendingRequestIfResultCannotBePersisted() async throws {
  let configuration = URLSessionConfiguration.ephemeral
  configuration.protocolClasses = [AcceptedResponseProtocol.self]
  let session = URLSession(configuration: configuration)
  defer { session.invalidateAndCancel() }
  let client = try GatePassClient(
    server: "http://127.0.0.1:8788", token: "fixture", session: session)
  let request: JSONObject = ["operation_id": "fixture", "ticket_secret": "private-fixture"]
  var outbox = ScanOutbox(
    operationID: "fixture", eventID: "event", deviceID: "device", request: request)
  do {
    _ = try await outbox.resolve(with: client, file: URL(fileURLWithPath: "/dev/null/outbox.json"))
    Issue.record("Expected outbox write failure")
  } catch {
    #expect(outbox.response == nil)
    #expect(outbox.request == request)
  }
}

@Test func restoredOutboxRejectsMismatchedAndIncompleteResults() async throws {
  var outbox = ScanOutbox(operationID: "op", eventID: "event", deviceID: "device", request: [:])
  outbox.response = ["operation_id": "different", "event_id": "event", "decision": "accepted"]
  let client = try GatePassClient(server: "http://127.0.0.1", token: "fixture")
  do {
    _ = try await outbox.resolve(with: client, file: URL(fileURLWithPath: "/dev/null"))
    Issue.record("Expected response validation")
  } catch { #expect(outbox.request != nil) }
  outbox.response = ["operation_id": "op", "event_id": "event", "decision": "accepted"]
  do {
    _ = try await outbox.resolve(with: client, file: URL(fileURLWithPath: "/dev/null"))
    Issue.record("Expected metadata validation")
  } catch { #expect(outbox.request != nil) }
}

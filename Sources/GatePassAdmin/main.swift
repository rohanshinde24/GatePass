import ArgumentParser
import CoreGraphics
import CoreImage
import CoreImage.CIFilterBuiltins
import CoreText
import Foundation
import GatePassProtocol
import ImageIO

private struct IssuedTicket: Codable {
  let id: String
  let externalID: String
  let displayName: String
  let email: String
  let secret: String
  var serverRecord: JSONObject {
    [
      "id": .string(id), "external_id": .string(externalID), "display_name": .string(displayName),
      "token_hash": .string(GatePassCrypto.hash(secret)),
    ]
  }
}
private struct IssuanceArchive: Codable {
  let eventID: String
  let batchID: String
  let sourceDigest: String
  let tickets: [IssuedTicket]
  var payload: JSONObject {
    ["batch_id": .string(batchID), "tickets": .array(tickets.map { .object($0.serverRecord) })]
  }
}

@main
struct Admin: AsyncParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "GatePassAdmin",
    abstract: "Issue event tickets and run recoverable online admission.")
  enum Action: String, ExpressibleByArgument {
    case eventCreate = "event-create"
    case rosterImport = "roster-import"
    case issuanceRecover = "issuance-recover"
    case deviceCreate = "device-create"
    case scan, resume, lookup, stats
    case attendanceExport = "attendance-export"
    case revokeTicket = "revoke-ticket"
    case revokeDevice = "revoke-device"
    case close
  }
  @Argument var action: Action
  @Option(help: "HTTPS origin or loopback HTTP for local development") var server =
    "http://127.0.0.1:8788"
  @Option(help: "Owner credential file; secrets are never accepted as arguments")
  var credentialFile = ".gatepass/owner.token"
  @Option var event: String?
  @Option var title = "Workshop"
  @Option var timezone = "America/Los_Angeles"
  @Option var csv: String?
  @Option var archive: String?
  @Option var keyFile: String?
  @Option var output: String?
  @Option var deviceFile: String?
  @Option var label = "Entrance A"
  @Option var ticket: String?
  @Option var ticketID: String?
  @Option var deviceID: String?
  @Option var outbox: String?
  @Option var operationID: String?
  @Option var query: String?
  @Option var id: String?
  @Flag var dryRun = false

  mutating func run() async throws {
    switch action {
    case .eventCreate:
      let eventID = try uuid(id ?? UUID().uuidString)
      try printJSON(
        try await owner().request(
          "POST", "/v1/admin/events",
          body: ["id": .string(eventID), "title": .string(title), "timezone": .string(timezone)]
        ).0)
    case .rosterImport:
      let eventID = try requiredEvent()
      let csvURL = try file(csv, "--csv")
      let raw = try Data(contentsOf: csvURL)
      let roster = try RosterCSV.parse(raw)
      if dryRun {
        try printJSON(["count": .number(Double(roster.count)), "valid": true])
        return
      }
      guard !roster.isEmpty else { throw ValidationError("Roster is empty") }
      let archiveURL = try file(archive, "--archive")
      let keyURL = archiveKey(archiveURL)
      let issued: IssuanceArchive
      if FileManager.default.fileExists(atPath: archiveURL.path) {
        issued = try readArchive(archiveURL, key: keyURL)
        guard issued.eventID == eventID, issued.sourceDigest == GatePassCrypto.hash(raw) else {
          throw ValidationError("Archive belongs to different source data or event")
        }
      } else {
        let key = GatePassCrypto.decodeToken(GatePassCrypto.randomToken())!
        if FileManager.default.fileExists(atPath: keyURL.path) {
          throw ValidationError(
            "Archive key already exists; use the original archive or another key path")
        }
        try PrivateFile.write(key, to: keyURL)
        issued = IssuanceArchive(
          eventID: eventID, batchID: UUID().uuidString.lowercased(),
          sourceDigest: GatePassCrypto.hash(raw),
          tickets: roster.map {
            IssuedTicket(
              id: UUID().uuidString.lowercased(), externalID: $0.externalID,
              displayName: $0.displayName, email: $0.email, secret: GatePassCrypto.randomToken())
          })
        try PrivateFile.write(
          GatePassCrypto.seal(GatePassCrypto.canonical(issued), key: key), to: archiveURL)
      }
      let result = try await owner().request(
        "POST", "/v1/admin/events/\(eventID)/imports", body: issued.payload)
      let destination = URL(
        fileURLWithPath: output ?? ".gatepass/tickets/\(issued.batchID)", isDirectory: true)
      try renderTickets(issued, to: destination)
      var response = result.0
      response["output"] = .string(destination.path)
      response["replayed"] = .bool(result.1)
      try printJSON(response)
    case .issuanceRecover:
      let archiveURL = try file(archive, "--archive")
      let issued = try readArchive(archiveURL, key: archiveKey(archiveURL))
      if let event {
        guard try uuid(event) == issued.eventID else {
          throw ValidationError("Wrong archive event")
        }
      }
      let stored = try await owner().request(
        "GET", "/v1/admin/events/\(issued.eventID)/imports/\(issued.batchID)"
      ).0
      let digest = GatePassCrypto.hash(
        try GatePassCrypto.canonical(issued.tickets.map { JSONValue.object($0.serverRecord) }))
      guard stored["payload_digest"]?.string == digest else {
        throw ValidationError("Committed import does not match the issuance archive")
      }
      let destination = URL(
        fileURLWithPath: output ?? ".gatepass/tickets/\(issued.batchID)", isDirectory: true)
      try renderTickets(issued, to: destination)
      try printJSON(["batch_id": .string(issued.batchID), "output": .string(destination.path)])
    case .deviceCreate:
      let eventID = try requiredEvent()
      let destination = try file(deviceFile ?? output, "--device-file")
      let setup: ScannerSetup
      if FileManager.default.fileExists(atPath: destination.path) {
        setup = try JSONDecoder().decode(ScannerSetup.self, from: Data(contentsOf: destination))
        guard setup.eventID == eventID, setup.server == server, setup.label == label else {
          throw ValidationError("Existing device setup has different configuration")
        }
      } else {
        setup = ScannerSetup(
          server: server, eventID: eventID, deviceID: UUID().uuidString.lowercased(), label: label,
          credential: GatePassCrypto.randomToken(),
          expiresAt: Date().addingTimeInterval(86400).ISO8601Format())
        try PrivateFile.write(GatePassCrypto.canonical(setup), to: destination)
      }
      let body: JSONObject = [
        "id": .string(setup.deviceID), "label": .string(setup.label),
        "credential_hash": .string(GatePassCrypto.hash(setup.credential)),
        "expires_at": .string(setup.expiresAt),
      ]
      let result = try await owner().request(
        "POST", "/v1/admin/events/\(eventID)/devices", body: body
      ).0
      if deviceFile != nil, let output {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = try GatePassCrypto.canonical(setup)
        guard let image = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
          let cg = CIContext().createCGImage(image, from: image.extent)
        else { throw GatePassError("Could not create staff setup QR") }
        let data = NSMutableData()
        guard
          let destination = CGImageDestinationCreateWithData(data, "public.png" as CFString, 1, nil)
        else { throw GatePassError("Could not encode staff setup QR") }
        CGImageDestinationAddImage(destination, cg, nil)
        guard CGImageDestinationFinalize(destination) else {
          throw GatePassError("Could not encode staff setup QR")
        }
        try PrivateFile.write(data as Data, to: URL(fileURLWithPath: output))
      }
      try printJSON(result)
    case .scan:
      let setup = try scanner()
      let eventID = setup.eventID
      let client = try GatePassClient(server: setup.server, token: setup.credential)
      let operation = try uuid(operationID ?? UUID().uuidString)
      let destination = URL(fileURLWithPath: outbox ?? ".gatepass/outbox/\(operation).json")
      guard !FileManager.default.fileExists(atPath: destination.path) else {
        throw ValidationError("Outbox already exists; use resume to recover it")
      }
      var request: JSONObject = ["operation_id": .string(operation)]
      if let ticketID {
        request["ticket_id"] = .string(try uuid(ticketID))
      } else {
        guard let ticket else { throw ValidationError("Provide --ticket or --ticket-id") }
        let raw =
          ticket.hasPrefix("@")
          ? try String(contentsOfFile: String(ticket.dropFirst()), encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines) : ticket
        let code = try TicketCode(raw)
        request["scanned_event_id"] = .string(code.eventID)
        request["ticket_secret"] = .string(code.secret)
      }
      var pending = ScanOutbox(
        operationID: operation, eventID: eventID, deviceID: setup.deviceID, request: request)
      try PrivateFile.write(GatePassCrypto.canonical(pending), to: destination)
      do {
        let result = try await pending.resolve(with: client, file: destination)
        var response = result.0
        response["replayed"] = .bool(result.1)
        response["outbox"] = .string(destination.path)
        try printJSON(response)
      } catch {
        throw GatePassError(
          "Admission not confirmed; preserve outbox and resume with --outbox \(destination.path). \(error.localizedDescription)"
        )
      }
    case .resume:
      let setup = try scanner()
      let destination = try file(outbox, "--outbox")
      var pending = try JSONDecoder().decode(ScanOutbox.self, from: Data(contentsOf: destination))
      guard pending.deviceID == setup.deviceID, pending.eventID == setup.eventID else {
        throw ValidationError("Outbox belongs to a different scanner")
      }
      let result = try await pending.resolve(
        with: GatePassClient(server: setup.server, token: setup.credential), file: destination)
      var response = result.0
      response["replayed"] = true
      response["review_required"] = true
      try printJSON(response)
    case .lookup, .stats:
      let setup = try scanner()
      let client = try GatePassClient(server: setup.server, token: setup.credential)
      var components = URLComponents()
      components.queryItems = [URLQueryItem(name: "q", value: query ?? "")]
      let encodedQuery = (components.percentEncodedQuery ?? "").replacingOccurrences(
        of: "+", with: "%2B")
      let suffix = action == .stats ? "stats" : "attendees?" + encodedQuery
      try printJSON(try await client.request("GET", "/v1/events/\(setup.eventID)/\(suffix)").0)
    case .attendanceExport:
      let response = try await owner().request(
        "GET", "/v1/admin/events/\(requiredEvent())/attendance"
      ).0
      guard let attendees = response["attendees"]?.array else {
        throw GatePassError("Invalid attendance response")
      }
      let columns = ["external_id", "display_name", "status", "admitted_at"]
      let csv =
        ([columns.joined(separator: ",")]
        + attendees.map { record in
          columns.map { RosterCSV.encodeCell(record.object?[$0]?.string ?? "") }.joined(
            separator: ",")
        }).joined(separator: "\n") + "\n"
      if let output {
        try PrivateFile.write(Data(csv.utf8), to: URL(fileURLWithPath: output))
        try printJSON(["output": .string(output), "count": .number(Double(attendees.count))])
      } else {
        print(csv, terminator: "")
      }
    case .revokeTicket:
      let eventID = try requiredEvent()
      let id = try uuid(ticketID ?? "")
      try printJSON(
        try await owner().request(
          "POST", "/v1/admin/events/\(eventID)/tickets/\(id)/revoke", body: [:]
        ).0)
    case .revokeDevice:
      let eventID = try requiredEvent()
      let id = try uuid(deviceID ?? "")
      try printJSON(
        try await owner().request(
          "POST", "/v1/admin/events/\(eventID)/devices/\(id)/revoke", body: [:]
        ).0)
    case .close:
      try printJSON(
        try await owner().request("POST", "/v1/admin/events/\(requiredEvent())/close", body: [:]).0)
    }
  }
  private func uuid(_ raw: String) throws -> String {
    guard let id = UUID(uuidString: raw) else { throw ValidationError("Expected a UUID") }
    return id.uuidString.lowercased()
  }
  private func requiredEvent() throws -> String { try uuid(event ?? "") }
  private func file(_ value: String?, _ flag: String) throws -> URL {
    guard let value else { throw ValidationError("Missing \(flag)") }
    return URL(fileURLWithPath: value)
  }
  private func owner() throws -> GatePassClient {
    let token = try String(contentsOfFile: credentialFile, encoding: .utf8).trimmingCharacters(
      in: .whitespacesAndNewlines)
    return try GatePassClient(server: server, token: token)
  }
  private func scanner() throws -> ScannerSetup {
    try JSONDecoder().decode(
      ScannerSetup.self, from: Data(contentsOf: file(deviceFile, "--device-file")))
  }
  private func archiveKey(_ archive: URL) -> URL {
    URL(
      fileURLWithPath: keyFile
        ?? ".gatepass/keys/\(GatePassCrypto.hash(archive.standardizedFileURL.path)).key")
  }
  private func readArchive(_ archive: URL, key: URL) throws -> IssuanceArchive {
    try JSONDecoder().decode(
      IssuanceArchive.self,
      from: GatePassCrypto.open(Data(contentsOf: archive), key: Data(contentsOf: key)))
  }
  private func printJSON(_ value: JSONObject) throws {
    print(String(decoding: try GatePassCrypto.canonical(value), as: UTF8.self))
  }
  private func renderTickets(_ archive: IssuanceArchive, to folder: URL) throws {
    try FileManager.default.createDirectory(
      at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    var index: [JSONValue] = []
    let context = CIContext()
    for ticket in archive.tickets {
      let code = try TicketCode(eventID: archive.eventID, secret: ticket.secret).rawValue
      let filter = CIFilter.qrCodeGenerator()
      filter.message = Data(code.utf8)
      filter.correctionLevel = "M"
      guard let image = filter.outputImage,
        let qr = context.createCGImage(image, from: image.extent)
      else { throw GatePassError("Could not generate ticket QR") }
      let pdf = folder.appendingPathComponent("\(ticket.id).pdf")
      var page = CGRect(x: 0, y: 0, width: 432, height: 540)
      guard let cg = CGContext(pdf as CFURL, mediaBox: &page, nil) else {
        throw GatePassError("Could not create ticket PDF")
      }
      cg.beginPDFPage(nil)
      cg.setFillColor(CGColor(gray: 1, alpha: 1))
      cg.fill(page)
      cg.interpolationQuality = .none
      cg.draw(qr, in: CGRect(x: 54, y: 150, width: 324, height: 324))
      let attributes: [NSAttributedString.Key: Any] = [
        NSAttributedString.Key(kCTFontAttributeName as String): CTFontCreateWithName(
          "Helvetica" as CFString, 16, nil)
      ]
      cg.textPosition = CGPoint(x: 30, y: 110)
      CTLineDraw(
        CTLineCreateWithAttributedString(
          NSAttributedString(string: ticket.displayName, attributes: attributes)), cg)
      cg.textPosition = CGPoint(x: 30, y: 80)
      CTLineDraw(
        CTLineCreateWithAttributedString(
          NSAttributedString(string: ticket.externalID, attributes: attributes)), cg)
      cg.endPDFPage()
      cg.closePDF()
      try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: pdf.path)
      try PrivateFile.write(
        Data(code.utf8), to: folder.appendingPathComponent("\(ticket.id).ticket"))
      index.append(
        .object([
          "id": .string(ticket.id), "external_id": .string(ticket.externalID),
          "display_name": .string(ticket.displayName), "email": .string(ticket.email),
          "pdf": .string(pdf.lastPathComponent),
        ]))
    }
    try PrivateFile.write(
      GatePassCrypto.canonical(index), to: folder.appendingPathComponent("index.json"))
  }
}

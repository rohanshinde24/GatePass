import Fluent
import FluentPostgresDriver
import Foundation
import GatePassProtocol
import SQLKit
import Vapor

extension Dictionary where Key == String, Value == JSONValue {
  fileprivate func string(_ key: String, maximum: Int = 1024) throws -> String {
    guard let value = self[key]?.string, !value.isEmpty, value.count <= maximum,
      !value.contains("\0")
    else { throw Abort(.badRequest, reason: "Invalid \(key)") }
    return value
  }
  fileprivate func uuid(_ key: String) throws -> String {
    guard let uuid = UUID(uuidString: try string(key)) else {
      throw Abort(.badRequest, reason: "Invalid \(key)")
    }
    return uuid.uuidString.lowercased()
  }
}

private func sqlDB(_ db: any Database) throws -> any SQLDatabase {
  guard let sql = db as? any SQLDatabase else {
    throw Abort(.internalServerError, reason: "SQL database unavailable")
  }
  return sql
}
private func json(_ value: JSONObject, replay: Bool = false, status: HTTPResponseStatus = .ok)
  throws -> Response
{
  var headers: HTTPHeaders = ["Content-Type": "application/json", "Cache-Control": "no-store"]
  if replay { headers.add(name: "GatePass-Replayed", value: "true") }
  return Response(
    status: status, headers: headers, body: .init(data: try GatePassCrypto.canonical(value)))
}
private func eventID(_ req: Request) throws -> String {
  guard let raw = req.parameters.get("event"), let id = UUID(uuidString: raw) else {
    throw Abort(.badRequest, reason: "Invalid event")
  }
  return id.uuidString.lowercased()
}
private func operationID(_ req: Request, _ name: String) throws -> String {
  guard let raw = req.parameters.get(name), let id = UUID(uuidString: raw) else {
    throw Abort(.badRequest, reason: "Invalid identifier")
  }
  return id.uuidString.lowercased()
}
private func checkHash(_ value: String) throws {
  guard value.count == 64,
    value.allSatisfy({ $0.isASCII && ($0.isNumber || ("a"..."f").contains(String($0))) })
  else { throw Abort(.badRequest, reason: "Invalid hash") }
}
private struct ScanResult: Sendable {
  let body: JSONObject
  let replay: Bool
}

public enum GatePassService {
  public static func configure(_ app: Application, databaseURL: String, ownerHash: String)
    async throws
  {
    app.http.server.configuration.hostname = "127.0.0.1"
    app.http.server.configuration.port = 8788
    app.routes.defaultMaxBodySize = "4mb"
    app.databases.use(
      try .postgres(url: databaseURL, maxConnectionsPerEventLoop: 2, sqlLogLevel: .critical),
      as: .psql)
    try await migrate(app.db)
    @Sendable func owner(_ req: Request) throws {
      guard let token = req.headers.bearerAuthorization?.token,
        GatePassCrypto.constantTimeEqual(GatePassCrypto.hash(token), ownerHash)
      else { throw Abort(.unauthorized) }
    }
    app.get("health") { _ in try json(["status": "ok"]) }

    app.post("v1", "admin", "events") { req async throws -> Response in
      try owner(req)
      let body = try req.content.decode(JSONObject.self)
      let title = try body.string("title", maximum: 200)
      let timezone = try body.string("timezone", maximum: 100)
      guard TimeZone(identifier: timezone) != nil else {
        throw Abort(.badRequest, reason: "Invalid timezone")
      }
      let id = try body.uuid("id")
      let sql = try sqlDB(req.db)
      try await sql.raw(
        "INSERT INTO events(id,title,timezone,status) VALUES (\(bind:id)::uuid,\(bind:title),\(bind:timezone),'active') ON CONFLICT(id) DO NOTHING"
      ).run()
      let row = try await sql.raw("SELECT title,timezone FROM events WHERE id=\(bind:id)::uuid")
        .first()!
      guard try row.decode(column: "title", as: String.self) == title,
        try row.decode(column: "timezone", as: String.self) == timezone
      else { throw Abort(.conflict, reason: "Event identifier reused") }
      return try json(["id": .string(id), "title": .string(title)])
    }
    app.post("v1", "admin", "events", ":event", "close") { req async throws -> Response in
      try owner(req)
      let event = try eventID(req)
      try await sqlDB(req.db).raw("UPDATE events SET status='closed' WHERE id=\(bind:event)::uuid")
        .run()
      return try json(["status": "closed"])
    }
    app.post("v1", "admin", "events", ":event", "imports") { req async throws -> Response in
      try owner(req)
      let event = try eventID(req)
      let body = try req.content.decode(JSONObject.self)
      let batch = try body.uuid("batch_id")
      guard let records = body["tickets"]?.array, !records.isEmpty, records.count <= 2000 else {
        throw Abort(.badRequest, reason: "Import requires 1 to 2,000 tickets")
      }
      var seenIDs = Set<String>()
      var seenTickets = Set<String>()
      var seenTokens = Set<String>()
      for record in records {
        guard let ticket = record.object else { throw Abort(.badRequest) }
        let external = try ticket.string("external_id", maximum: 128)
        let name = try ticket.string("display_name", maximum: 200)
        let id = try ticket.uuid("id")
        let hash = try ticket.string("token_hash")
        try checkHash(hash)
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
          seenIDs.insert(external).inserted, seenTickets.insert(id).inserted,
          seenTokens.insert(hash).inserted
        else { throw Abort(.badRequest, reason: "Duplicate import identity") }
      }
      let digest = GatePassCrypto.hash(try GatePassCrypto.canonical(records))
      let outcome = try await req.db.transaction { db async throws -> Bool in
        let sql = try sqlDB(db)
        guard
          try await sql.raw(
            "SELECT id FROM events WHERE id=\(bind:event)::uuid AND status='active' FOR SHARE"
          ).first() != nil
        else { throw Abort(.notFound) }
        try await sql.raw(
          "SELECT pg_advisory_xact_lock(\(bind:lockKey("import:" + event + ":" + batch)))"
        ).run()
        if let prior = try await sql.raw(
          "SELECT payload_digest FROM import_batches WHERE event_id=\(bind:event)::uuid AND id=\(bind:batch)::uuid"
        ).first() {
          guard try prior.decode(column: "payload_digest", as: String.self) == digest else {
            throw Abort(.conflict, reason: "Import identifier reused with different data")
          }
          return true
        }
        try await sql.raw(
          "INSERT INTO import_batches(id,event_id,payload_digest,ticket_count) VALUES (\(bind:batch)::uuid,\(bind:event)::uuid,\(bind:digest),\(bind:records.count))"
        ).run()
        for record in records {
          let ticket = record.object!
          try await sql.raw(
            "INSERT INTO tickets(id,event_id,external_id,display_name,token_hash,status) VALUES (\(bind:try ticket.uuid("id"))::uuid,\(bind:event)::uuid,\(bind:try ticket.string("external_id")),\(bind:try ticket.string("display_name")),\(bind:try ticket.string("token_hash")),'issued')"
          ).run()
        }
        return false
      }
      return try json(
        [
          "batch_id": .string(batch), "count": .number(Double(records.count)),
          "payload_digest": .string(digest),
        ], replay: outcome)
    }
    app.get("v1", "admin", "events", ":event", "imports", ":batch") {
      req async throws -> Response in
      try owner(req)
      let event = try eventID(req)
      let batch = try operationID(req, "batch")
      guard
        let row = try await sqlDB(req.db).raw(
          "SELECT payload_digest,ticket_count FROM import_batches WHERE event_id=\(bind:event)::uuid AND id=\(bind:batch)::uuid"
        ).first()
      else { throw Abort(.notFound) }
      return try json([
        "batch_id": .string(batch),
        "payload_digest": .string(try row.decode(column: "payload_digest", as: String.self)),
        "count": .number(Double(try row.decode(column: "ticket_count", as: Int.self))),
      ])
    }
    app.post("v1", "admin", "events", ":event", "devices") { req async throws -> Response in
      try owner(req)
      let event = try eventID(req)
      let body = try req.content.decode(JSONObject.self)
      let id = try body.uuid("id")
      let label = try body.string("label", maximum: 100)
      let hash = try body.string("credential_hash")
      try checkHash(hash)
      let expires = try body.string("expires_at")
      guard let date = ISO8601DateFormatter().date(from: expires), date > Date() else {
        throw Abort(.badRequest, reason: "Expiry must be a future ISO8601 date")
      }
      let sql = try sqlDB(req.db)
      try await sql.raw(
        "INSERT INTO staff_devices(id,event_id,label,credential_hash,expires_at) VALUES (\(bind:id)::uuid,\(bind:event)::uuid,\(bind:label),\(bind:hash),\(bind:date)) ON CONFLICT(id) DO NOTHING"
      ).run()
      guard
        let row = try await sql.raw(
          "SELECT label,credential_hash,expires_at FROM staff_devices WHERE id=\(bind:id)::uuid AND event_id=\(bind:event)::uuid"
        ).first(),
        try row.decode(column: "label", as: String.self) == label,
        try row.decode(column: "credential_hash", as: String.self) == hash,
        abs(try row.decode(column: "expires_at", as: Date.self).timeIntervalSince(date)) < 0.001
      else { throw Abort(.conflict, reason: "Device identifier reused") }
      return try json(["id": .string(id), "label": .string(label)])
    }
    app.post("v1", "admin", "events", ":event", "devices", ":device", "revoke") {
      req async throws -> Response in
      try owner(req)
      let event = try eventID(req)
      let device = try operationID(req, "device")
      try await sqlDB(req.db).raw(
        "UPDATE staff_devices SET revoked_at=COALESCE(revoked_at,now()) WHERE event_id=\(bind:event)::uuid AND id=\(bind:device)::uuid"
      ).run()
      return try json(["status": "revoked"])
    }
    app.post("v1", "admin", "events", ":event", "tickets", ":ticket", "revoke") {
      req async throws -> Response in
      try owner(req)
      let event = try eventID(req)
      let ticket = try operationID(req, "ticket")
      try await req.db.transaction { db async throws in
        let sql = try sqlDB(db)
        _ = try await sql.raw("SELECT id FROM events WHERE id=\(bind:event)::uuid FOR SHARE")
          .first()
        guard
          let row = try await sql.raw(
            "SELECT status FROM tickets WHERE event_id=\(bind:event)::uuid AND id=\(bind:ticket)::uuid FOR UPDATE"
          ).first()
        else { throw Abort(.notFound) }
        guard try row.decode(column: "status", as: String.self) != "admitted" else {
          throw Abort(.conflict, reason: "Admitted ticket cannot be revoked")
        }
        try await sql.raw(
          "UPDATE tickets SET status='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE id=\(bind:ticket)::uuid"
        ).run()
      }
      return try json(["status": "revoked"])
    }
    app.on(.POST, "v1", "events", ":event", "scans", body: .collect(maxSize: "8kb")) {
      req async throws -> Response in
      let result = try await decide(req, manual: false)
      return try json(result.body, replay: result.replay)
    }
    app.on(.POST, "v1", "events", ":event", "manual-scans", body: .collect(maxSize: "8kb")) {
      req async throws -> Response in
      let result = try await decide(req, manual: true)
      return try json(result.body, replay: result.replay)
    }
    app.get("v1", "events", ":event", "devices", "me", "scans", ":operation") {
      req async throws -> Response in
      let event = try eventID(req)
      let operation = try operationID(req, "operation")
      let device = try await authorizedDevice(req, event: event, db: req.db)
      guard
        let row = try await sqlDB(req.db).raw(
          "SELECT response_json FROM scan_operations WHERE event_id=\(bind:event)::uuid AND device_id=\(bind:device.id)::uuid AND operation_id=\(bind:operation)::uuid"
        ).first()
      else { throw Abort(.notFound) }
      let value = try JSONDecoder().decode(
        JSONObject.self, from: Data(try row.decode(column: "response_json", as: String.self).utf8))
      return try json(value, replay: true)
    }
    app.get("v1", "events", ":event", "attendees") { req async throws -> Response in
      let event = try eventID(req)
      _ = try await authorizedDevice(req, event: event, db: req.db)
      let query = String((req.query[String.self, at: "q"] ?? "").prefix(100))
      guard !query.isEmpty else { return try json(["attendees": .array([])]) }
      let rows = try await sqlDB(req.db).raw(
        "SELECT id::text,display_name,status FROM tickets WHERE event_id=\(bind:event)::uuid AND strpos(lower(display_name),lower(\(bind:query)))>0 ORDER BY display_name LIMIT 25"
      ).all()
      return try json([
        "attendees": .array(
          try rows.map {
            .object([
              "id": .string(try $0.decode(column: "id", as: String.self)),
              "display_name": .string(try $0.decode(column: "display_name", as: String.self)),
              "status": .string(try $0.decode(column: "status", as: String.self)),
            ])
          })
      ])
    }
    app.get("v1", "events", ":event", "stats") { req async throws -> Response in
      let event = try eventID(req)
      _ = try await authorizedDevice(req, event: event, db: req.db)
      let row = try await sqlDB(req.db).raw(
        "SELECT count(*)::int AS count FROM admissions WHERE event_id=\(bind:event)::uuid"
      ).first()!
      return try json(["admitted": .number(Double(try row.decode(column: "count", as: Int.self)))])
    }
    app.get("v1", "admin", "events", ":event", "attendance") { req async throws -> Response in
      try owner(req)
      let event = try eventID(req)
      let rows = try await sqlDB(req.db).raw(
        "SELECT id::text,external_id,display_name,status,admitted_at FROM tickets WHERE event_id=\(bind:event)::uuid ORDER BY external_id"
      ).all()
      return try json([
        "attendees": .array(
          try rows.map { row in
            let date = try row.decode(column: "admitted_at", as: Date?.self)
            return .object([
              "id": .string(try row.decode(column: "id", as: String.self)),
              "external_id": .string(try row.decode(column: "external_id", as: String.self)),
              "display_name": .string(try row.decode(column: "display_name", as: String.self)),
              "status": .string(try row.decode(column: "status", as: String.self)),
              "admitted_at": date.map { .string($0.ISO8601Format()) } ?? .null,
            ])
          })
      ])
    }
  }

  private struct Device: Sendable {
    let id: String
    let label: String
  }
  private static func authorizedDevice(
    _ req: Request, event: String, db: any Database, locked: Bool = false
  ) async throws -> Device {
    guard let token = req.headers.bearerAuthorization?.token else { throw Abort(.unauthorized) }
    let hash = GatePassCrypto.hash(token)
    let sql = try sqlDB(db)
    let query: SQLQueryString =
      "SELECT id::text,label FROM staff_devices WHERE event_id=\(bind:event)::uuid AND credential_hash=\(bind:hash) AND revoked_at IS NULL AND expires_at>now()"
    let rows = try await sql.raw(locked ? query + " FOR SHARE" : query).all()
    guard let row = rows.first else { throw Abort(.unauthorized) }
    return Device(
      id: try row.decode(column: "id", as: String.self),
      label: try row.decode(column: "label", as: String.self))
  }

  private static func decide(_ req: Request, manual: Bool) async throws -> ScanResult {
    let event = try eventID(req)
    let body = try req.content.decode(JSONObject.self)
    let operation = try body.uuid("operation_id")
    let scannedEvent = manual ? event : try body.uuid("scanned_event_id")
    let identity: String
    if manual {
      identity = try body.uuid("ticket_id")
    } else {
      let secret = try body.string("ticket_secret")
      guard GatePassCrypto.decodeToken(secret) != nil else {
        throw Abort(.badRequest, reason: "Invalid ticket secret")
      }
      identity = GatePassCrypto.hash(secret)
    }
    let digest = GatePassCrypto.hash(
      try GatePassCrypto.canonical([
        "version": "v1", "kind": manual ? "manual" : "qr", "event": event,
        "scanned_event": scannedEvent, "identity": identity,
      ]))
    return try await req.db.transaction { db async throws -> ScanResult in
      let sql = try sqlDB(db)
      guard
        let eventRow = try await sql.raw(
          "SELECT status FROM events WHERE id=\(bind:event)::uuid FOR SHARE"
        ).first()
      else { throw Abort(.forbidden) }
      let device = try await authorizedDevice(req, event: event, db: db, locked: true)
      try await sql.raw(
        "SELECT pg_advisory_xact_lock(\(bind:lockKey("scan:" + event + ":" + device.id + ":" + operation)))"
      ).run()
      if let prior = try await sql.raw(
        "SELECT request_digest,response_json FROM scan_operations WHERE event_id=\(bind:event)::uuid AND device_id=\(bind:device.id)::uuid AND operation_id=\(bind:operation)::uuid"
      ).first() {
        guard try prior.decode(column: "request_digest", as: String.self) == digest else {
          throw Abort(.conflict, reason: "Operation identifier reused with different request")
        }
        return ScanResult(
          body: try JSONDecoder().decode(
            JSONObject.self,
            from: Data(try prior.decode(column: "response_json", as: String.self).utf8)),
          replay: true)
      }
      var response: JSONObject = ["operation_id": .string(operation), "event_id": .string(event)]
      if try eventRow.decode(column: "status", as: String.self) != "active" {
        response["decision"] = "event_closed"
      } else if scannedEvent != event {
        response["decision"] = "wrong_event"
      } else {
        let selector: SQLQueryString =
          manual ? "id=\(bind:identity)::uuid" : "token_hash=\(bind:identity)"
        if let row = try await sql.raw(
          "SELECT id::text,display_name,status,admitted_at,admitted_device_id::text FROM tickets WHERE event_id=\(bind:event)::uuid AND "
            + selector + " FOR UPDATE"
        ).first() {
          let status = try row.decode(column: "status", as: String.self)
          let ticket = try row.decode(column: "id", as: String.self)
          response["ticket_id"] = .string(ticket)
          response["display_name"] = .string(
            try row.decode(column: "display_name", as: String.self))
          if status == "revoked" {
            response["decision"] = "revoked"
          } else if status == "admitted" {
            response["decision"] = "already_admitted"
            response["admitted_at"] = .string(
              try row.decode(column: "admitted_at", as: Date.self).ISO8601Format())
            let admittedDevice = try row.decode(column: "admitted_device_id", as: String.self)
            let staff = try await sql.raw(
              "SELECT label FROM staff_devices WHERE id=\(bind:admittedDevice)::uuid AND event_id=\(bind:event)::uuid"
            ).first()
            response["admitted_by"] = .string(
              try staff?.decode(column: "label", as: String.self) ?? "Recorded scanner")
          } else {
            let admittedAt = Date()
            try await sql.raw(
              "UPDATE tickets SET status='admitted',admitted_at=\(bind:admittedAt),admitted_device_id=\(bind:device.id)::uuid WHERE id=\(bind:ticket)::uuid"
            ).run()
            try await sql.raw(
              "INSERT INTO admissions(ticket_id,event_id,device_id,operation_id,admitted_at) VALUES (\(bind:ticket)::uuid,\(bind:event)::uuid,\(bind:device.id)::uuid,\(bind:operation)::uuid,\(bind:admittedAt))"
            ).run()
            response["decision"] = "accepted"
            response["admitted_at"] = .string(admittedAt.ISO8601Format())
            response["admitted_by"] = .string(device.label)
          }
        } else {
          response["decision"] = "invalid_ticket"
        }
      }
      let encoded = String(decoding: try GatePassCrypto.canonical(response), as: UTF8.self)
      try await sql.raw(
        "INSERT INTO scan_operations(event_id,device_id,operation_id,request_digest,response_json) VALUES (\(bind:event)::uuid,\(bind:device.id)::uuid,\(bind:operation)::uuid,\(bind:digest),\(bind:encoded))"
      ).run()
      return ScanResult(body: response, replay: false)
    }
  }
  private static func lockKey(_ identity: String) -> Int64 {
    let hex = String(GatePassCrypto.hash(identity).prefix(16))
    return Int64(bitPattern: UInt64(hex, radix: 16)!)
  }
  public static func migrate(_ db: any Database) async throws {
    let statements = [
      "CREATE TABLE IF NOT EXISTS events(id uuid PRIMARY KEY,title text NOT NULL,timezone text NOT NULL,status text NOT NULL CHECK(status IN ('active','closed')))",
      "CREATE TABLE IF NOT EXISTS staff_devices(id uuid PRIMARY KEY,event_id uuid NOT NULL REFERENCES events(id),label text NOT NULL,credential_hash text UNIQUE NOT NULL,expires_at timestamptz NOT NULL,revoked_at timestamptz,UNIQUE(event_id,id))",
      "CREATE TABLE IF NOT EXISTS import_batches(id uuid PRIMARY KEY,event_id uuid NOT NULL REFERENCES events(id),payload_digest text NOT NULL,ticket_count integer NOT NULL,committed_at timestamptz NOT NULL DEFAULT now())",
      "CREATE TABLE IF NOT EXISTS tickets(id uuid PRIMARY KEY,event_id uuid NOT NULL REFERENCES events(id),external_id text NOT NULL,display_name text NOT NULL,token_hash text UNIQUE NOT NULL,status text NOT NULL CHECK(status IN ('issued','admitted','revoked')),admitted_at timestamptz,admitted_device_id uuid,revoked_at timestamptz,UNIQUE(event_id,external_id),UNIQUE(event_id,id),FOREIGN KEY(event_id,admitted_device_id) REFERENCES staff_devices(event_id,id),CONSTRAINT ticket_admission_metadata CHECK((status='admitted' AND admitted_at IS NOT NULL AND admitted_device_id IS NOT NULL) OR (status IN ('issued','revoked') AND admitted_at IS NULL AND admitted_device_id IS NULL)),CHECK((status='revoked')=(revoked_at IS NOT NULL)))",
      "CREATE TABLE IF NOT EXISTS scan_operations(event_id uuid NOT NULL,device_id uuid NOT NULL,operation_id uuid NOT NULL,request_digest text NOT NULL,response_json text NOT NULL,completed_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(event_id,device_id,operation_id),FOREIGN KEY(event_id,device_id) REFERENCES staff_devices(event_id,id))",
      "CREATE TABLE IF NOT EXISTS admissions(ticket_id uuid PRIMARY KEY,event_id uuid NOT NULL,device_id uuid NOT NULL,operation_id uuid NOT NULL,admitted_at timestamptz NOT NULL,FOREIGN KEY(event_id,ticket_id) REFERENCES tickets(event_id,id),FOREIGN KEY(event_id,device_id,operation_id) REFERENCES scan_operations(event_id,device_id,operation_id) DEFERRABLE INITIALLY DEFERRED)",
    ]
    try await db.transaction { transaction async throws in
      let sql = try sqlDB(transaction)
      try await sql.raw("SELECT pg_advisory_xact_lock(8374291001)").run()
      for statement in statements {
        try await sql.raw(SQLQueryString(stringLiteral: statement)).run()
      }
    }
  }
}

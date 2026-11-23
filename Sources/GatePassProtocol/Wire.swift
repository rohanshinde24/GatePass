import CryptoKit
import Foundation

#if canImport(Darwin)
  import Darwin
#else
  import Glibc
#endif

public enum JSONValue: Codable, Sendable, Equatable, ExpressibleByStringLiteral,
  ExpressibleByIntegerLiteral, ExpressibleByBooleanLiteral
{
  case string(String)
  case number(Double)
  case bool(Bool)
  case object([String: JSONValue])
  case array([JSONValue])
  case null
  public init(stringLiteral value: String) { self = .string(value) }
  public init(integerLiteral value: Int) { self = .number(Double(value)) }
  public init(booleanLiteral value: Bool) { self = .bool(value) }
  public init(from decoder: any Decoder) throws {
    let c = try decoder.singleValueContainer()
    if c.decodeNil() {
      self = .null
    } else if let v = try? c.decode(Bool.self) {
      self = .bool(v)
    } else if let v = try? c.decode(String.self) {
      self = .string(v)
    } else if let v = try? c.decode(Double.self) {
      self = .number(v)
    } else if let v = try? c.decode([String: JSONValue].self) {
      self = .object(v)
    } else {
      self = .array(try c.decode([JSONValue].self))
    }
  }
  public func encode(to encoder: any Encoder) throws {
    var c = encoder.singleValueContainer()
    switch self {
    case .string(let v): try c.encode(v)
    case .number(let v): try c.encode(v)
    case .bool(let v): try c.encode(v)
    case .object(let v): try c.encode(v)
    case .array(let v): try c.encode(v)
    case .null: try c.encodeNil()
    }
  }
  public var string: String? {
    if case .string(let v) = self { return v }
    return nil
  }
  public var array: [JSONValue]? {
    if case .array(let v) = self { return v }
    return nil
  }
  public var object: JSONObject? {
    if case .object(let v) = self { return v }
    return nil
  }
  public var integer: Int? {
    if case .number(let v) = self, v.isFinite, v.rounded() == v, v >= Double(Int.min),
      v < Double(Int.max)
    {
      return Int(v)
    }
    return nil
  }
}
public typealias JSONObject = [String: JSONValue]

public struct GatePassError: Error, LocalizedError, Sendable {
  public let message: String
  public init(_ message: String) { self.message = message }
  public var errorDescription: String? { message }
}

public enum GatePassCrypto {
  public static func randomToken() -> String {
    let key = SymmetricKey(size: .bits256)
    return key.withUnsafeBytes {
      Data($0).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(
        of: "/", with: "_"
      ).replacingOccurrences(of: "=", with: "")
    }
  }
  public static func decodeToken(_ token: String) -> Data? {
    guard token.count == 43,
      token.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
    else { return nil }
    let raw =
      token.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "="
    guard let bytes = Data(base64Encoded: raw), bytes.count == 32 else { return nil }
    return bytes
  }
  public static func hash(_ value: String) -> String { hash(Data(value.utf8)) }
  public static func hash(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }
  public static func canonical<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try encoder.encode(value)
  }
  public static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
    let left = Array(a.utf8)
    let right = Array(b.utf8)
    guard left.count == right.count else { return false }
    return zip(left, right).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
  }
  public static func seal(_ data: Data, key: Data) throws -> Data {
    guard key.count == 32,
      let combined = try AES.GCM.seal(data, using: SymmetricKey(data: key)).combined
    else { throw GatePassError("Invalid archive key") }
    return combined
  }
  public static func open(_ data: Data, key: Data) throws -> Data {
    guard key.count == 32 else { throw GatePassError("Invalid archive key") }
    return try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: SymmetricKey(data: key))
  }
}

public struct TicketCode: Codable, Sendable, Equatable {
  public let eventID: String
  public let secret: String
  public init(eventID: String, secret: String) throws {
    guard let event = UUID(uuidString: eventID), GatePassCrypto.decodeToken(secret) != nil else {
      throw GatePassError("Invalid GatePass ticket")
    }
    self.eventID = event.uuidString.lowercased()
    self.secret = secret
  }
  public init(_ code: String) throws {
    let fields = code.split(separator: ":", omittingEmptySubsequences: false)
    guard fields.count == 4, fields[0] == "gatepass", fields[1] == "v1" else {
      throw GatePassError("Unsupported GatePass ticket")
    }
    try self.init(eventID: String(fields[2]), secret: String(fields[3]))
  }
  public var rawValue: String { "gatepass:v1:\(eventID):\(secret)" }
}

public struct RosterEntry: Codable, Sendable, Equatable {
  public let externalID: String
  public let displayName: String
  public let email: String
  public init(externalID: String, displayName: String, email: String = "") {
    self.externalID = externalID
    self.displayName = displayName
    self.email = email
  }
}

public enum RosterCSV {
  public static func parse(_ data: Data) throws -> [RosterEntry] {
    guard data.count <= 2 * 1024 * 1024, var text = String(data: data, encoding: .utf8) else {
      throw GatePassError("Roster must be UTF-8 and at most 2 MiB")
    }
    if text.first == "\u{feff}" { text.removeFirst() }
    let rows = try cells(text).filter { !$0.allSatisfy(\.isEmpty) }
    guard let header = rows.first, Set(header).count == header.count,
      let id = header.firstIndex(of: "external_id"),
      let name = header.firstIndex(of: "display_name")
    else { throw GatePassError("Roster needs unique external_id and display_name headers") }
    guard rows.count <= 2001 else { throw GatePassError("Roster exceeds 2,000 attendees") }
    let email = header.firstIndex(of: "email")
    var seen = Set<String>()
    return try rows.dropFirst().map { row in
      guard row.count == header.count else {
        throw GatePassError("CSV row has the wrong column count")
      }
      let externalID = row[id]
      let displayName = row[name]
      guard !externalID.isEmpty, externalID.count <= 128,
        !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
        displayName.count <= 200,
        !externalID.contains("\0"), !displayName.contains("\0"), seen.insert(externalID).inserted
      else { throw GatePassError("Roster contains invalid or duplicate attendee identifiers") }
      return RosterEntry(
        externalID: externalID, displayName: displayName, email: email.map { row[$0] } ?? "")
    }
  }
  public static func cells(_ text: String) throws -> [[String]] {
    var rows: [[String]] = []
    var row: [String] = []
    var field = ""
    var quoted = false
    var closed = false
    var fieldStart = true
    let chars = Array(text)
    var i = 0
    while i < chars.count {
      let ch = chars[i]
      if quoted {
        if ch == "\"" {
          if i + 1 < chars.count && chars[i + 1] == "\"" {
            field.append("\"")
            i += 1
          } else {
            quoted = false
            closed = true
          }
        } else {
          field.append(ch)
        }
      } else if ch == "," {
        row.append(field)
        field = ""
        fieldStart = true
        closed = false
      } else if ch == "\n" || ch == "\r\n" || ch == "\r" {
        row.append(field)
        rows.append(row)
        row = []
        field = ""
        fieldStart = true
        closed = false
        if ch == "\r", i + 1 < chars.count, chars[i + 1] == "\n" { i += 1 }
      } else if ch == "\"" && fieldStart {
        quoted = true
        fieldStart = false
      } else {
        guard !closed, ch != "\"" else { throw GatePassError("Malformed CSV quoting") }
        field.append(ch)
        fieldStart = false
      }
      i += 1
    }
    guard !quoted else { throw GatePassError("Unterminated CSV field") }
    if !row.isEmpty || !field.isEmpty || closed {
      row.append(field)
      rows.append(row)
    }
    return rows
  }
  public static func encodeCell(_ value: String) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    let safe =
      ["=", "+", "-", "@"].contains(String(trimmed.prefix(1))) || value.first == "\t"
        || value.first == "\r" ? "'" + value : value
    return "\"" + safe.replacingOccurrences(of: "\"", with: "\"\"") + "\""
  }
}

public enum PrivateFile {
  public static func write(_ data: Data, to url: URL) throws {
    try FileManager.default.createDirectory(
      at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    let tmp = url.deletingLastPathComponent().appendingPathComponent(".\(UUID().uuidString).tmp")
    guard
      FileManager.default.createFile(
        atPath: tmp.path, contents: nil, attributes: [.posixPermissions: 0o600])
    else { throw GatePassError("Could not create private file") }
    do {
      let file = try FileHandle(forWritingTo: tmp)
      try file.write(contentsOf: data)
      try file.synchronize()
      try file.close()
      if rename(tmp.path, url.path) != 0 { throw GatePassError("Could not replace private file") }
      let directory = open(url.deletingLastPathComponent().path, O_RDONLY)
      guard directory >= 0 else { throw GatePassError("Could not open private parent directory") }
      defer { close(directory) }
      guard fsync(directory) == 0 else {
        throw GatePassError("Could not synchronize private parent directory")
      }
    } catch {
      try? FileManager.default.removeItem(at: tmp)
      throw error
    }
  }
}

import AVFoundation
import GatePassProtocol
import Security
import SwiftUI

@main
struct GatePassScannerApp: App {
  @StateObject private var model = ScannerModel()
  var body: some Scene {
    WindowGroup {
      ContentView(model: model).task { await model.restore() }
    }
  }
}

@MainActor
final class ScannerModel: ObservableObject {
  @Published var setup: ScannerSetup?
  @Published var status = "Set up your scanner"
  @Published var checking = false
  @Published var result: JSONObject?
  @Published var recoveredResult = false
  @Published var pending = false
  @Published var setupText = ""
  @Published var lookupText = ""
  @Published var matches: [JSONObject] = []
  @Published var cameraAllowed = false
  @Published var restoring = true
  @Published var recoveryBlocked = false
  private var currentOutbox: ScanOutbox?
  private let file: URL = {
    FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
      .appendingPathComponent("GatePass/pending.json")
  }()

  func restore() async {
    guard restoring else { return }
    do {
      if let data = try SetupKeychain.read() {
        setup = try JSONDecoder().decode(ScannerSetup.self, from: data)
      }
      if FileManager.default.fileExists(atPath: file.path) {
        currentOutbox = try JSONDecoder().decode(ScanOutbox.self, from: Data(contentsOf: file))
        if let outbox = currentOutbox, !outbox.acknowledged {
          pending = true
          guard let setup, outbox.eventID == setup.eventID, outbox.deviceID == setup.deviceID else {
            throw GatePassError(
              "Pending scan requires its original staff credentials. Do not replace this device's setup."
            )
          }
        }
      }
      restoring = false
      if pending {
        await resolve(recovered: true)
      } else {
        status = setup == nil ? "Scan a staff setup QR or paste its JSON" : "Ready to scan"
      }
      cameraAllowed = await AVCaptureDevice.requestAccess(for: .video)
    } catch {
      recoveryBlocked = true
      pending = true
      restoring = false
      status = "Recovery blocked: \(error.localizedDescription)"
    }
  }
  func installSetup(_ raw: String) {
    guard !restoring, !recoveryBlocked, !pending, !checking else { return }
    do {
      let data = Data(raw.utf8)
      let next = try JSONDecoder().decode(ScannerSetup.self, from: data)
      guard UUID(uuidString: next.eventID) != nil, UUID(uuidString: next.deviceID) != nil,
        GatePassCrypto.decodeToken(next.credential) != nil
      else { throw GatePassError("Invalid staff setup") }
      _ = try GatePassClient(server: next.server, token: next.credential)
      try SetupKeychain.save(data)
      setup = next
      setupText = ""
      status = "Ready to scan"
      result = nil
    } catch { status = "Setup failed: \(error.localizedDescription)" }
  }
  func received(_ value: String) {
    guard !restoring, !recoveryBlocked, !checking, !pending, result == nil else { return }
    if setup == nil {
      installSetup(value)
      return
    }
    Task { await scan(value) }
  }
  func scan(_ value: String) async {
    do {
      let code = try TicketCode(value)
      await begin([
        "scanned_event_id": .string(code.eventID), "ticket_secret": .string(code.secret),
      ])
    } catch { status = error.localizedDescription }
  }
  func manual(_ ticket: JSONObject) async {
    guard let id = ticket["id"]?.string else { return }
    await begin(["ticket_id": .string(id)])
  }
  private func begin(_ fields: JSONObject) async {
    guard !restoring, !recoveryBlocked, let setup, !checking, !pending, result == nil else {
      return
    }
    let operation = UUID().uuidString.lowercased()
    var request = fields
    request["operation_id"] = .string(operation)
    let outbox = ScanOutbox(
      operationID: operation, eventID: setup.eventID, deviceID: setup.deviceID, request: request)
    do {
      try PrivateFile.write(GatePassCrypto.canonical(outbox), to: file)
      currentOutbox = outbox
      pending = true
      try FileManager.default.setAttributes(
        [.protectionKey: FileProtectionType.complete], ofItemAtPath: file.path)
      await resolve(recovered: false)
    } catch { status = "Could not save the scan safely: \(error.localizedDescription)" }
  }
  func resolve(recovered: Bool = true) async {
    guard !restoring, !recoveryBlocked, let setup, var outbox = currentOutbox, !checking else {
      return
    }
    guard outbox.eventID == setup.eventID, outbox.deviceID == setup.deviceID else {
      status = "Pending scan belongs to another staff device"
      pending = true
      return
    }
    checking = true
    pending = true
    status = "Checking admission…"
    defer { checking = false }
    do {
      let (response, replayed) = try await outbox.resolve(
        with: GatePassClient(server: setup.server, token: setup.credential), file: file)
      currentOutbox = outbox
      result = response
      recoveredResult = recovered || replayed
      pending = false
      matches = []
      let decision = response["decision"]?.string ?? "unknown"
      status =
        recovered || replayed
        ? "Previously recorded — review before admitting"
        : decision.replacingOccurrences(of: "_", with: " ").capitalized
      if decision == "accepted", !recovered, !replayed {
        UINotificationFeedbackGenerator().notificationOccurred(.success)
      }
    } catch { status = "Not confirmed. Restore connectivity, then retry." }
  }
  func acknowledge() {
    guard var outbox = currentOutbox, !pending, !checking else { return }
    do {
      outbox.acknowledged = true
      try PrivateFile.write(GatePassCrypto.canonical(outbox), to: file)
      currentOutbox = outbox
      result = nil
      status = "Ready to scan"
    } catch { status = "Could not acknowledge the result safely" }
  }
  func lookup() async {
    guard !restoring, !recoveryBlocked, let setup, !pending, !checking else { return }
    checking = true
    defer { checking = false }
    do {
      var components = URLComponents()
      components.queryItems = [URLQueryItem(name: "q", value: lookupText)]
      let query = (components.percentEncodedQuery ?? "q=").replacingOccurrences(
        of: "+", with: "%2B")
      let response = try await GatePassClient(server: setup.server, token: setup.credential)
        .request("GET", "/v1/events/\(setup.eventID)/attendees?\(query)")
      matches = response.0["attendees"]?.array?.compactMap(\.object) ?? []
    } catch { status = "Lookup unavailable" }
  }
}

struct ContentView: View {
  @ObservedObject var model: ScannerModel
  var body: some View {
    NavigationStack {
      ScrollView {
        VStack(alignment: .leading, spacing: 16) {
          if let setup = model.setup {
            Text(setup.label).font(.title2.bold())
            Text("Event \(setup.eventID)").font(.caption).foregroundStyle(.secondary)
          }
          Text(model.status).font(.headline).accessibilityAddTraits(.updatesFrequently)
          if let result = model.result {
            Label(
              model.recoveredResult
                ? "Previously recorded — review"
                : (result["decision"]?.string?.replacingOccurrences(of: "_", with: " ").capitalized
                  ?? "Recorded"),
              systemImage: result["decision"]?.string == "accepted" && !model.recoveredResult
                ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
            )
            .font(.title2).foregroundStyle(
              result["decision"]?.string == "accepted" && !model.recoveredResult
                ? Color.green : Color.orange)
            if let name = result["display_name"]?.string { Text(name).font(.title3) }
            if let time = result["admitted_at"]?.string { Text("Recorded: \(time)").font(.caption) }
            if let staff = result["admitted_by"]?.string {
              Text("Scanner: \(staff)").font(.caption)
            }
            Button("Acknowledge and scan next") { model.acknowledge() }.buttonStyle(
              .borderedProminent)
          } else if model.restoring {
            ProgressView("Restoring scanner…")
          } else if model.recoveryBlocked {
            Label(
              "Recovery requires the original local scanner state",
              systemImage: "lock.trianglebadge.exclamationmark")
          } else if model.pending {
            Label("Admission is not confirmed", systemImage: "wifi.exclamationmark")
              .foregroundStyle(.orange)
            Button("Retry pending scan") { Task { await model.resolve() } }.disabled(model.checking)
          } else {
            if model.cameraAllowed {
              QRScanner(onCode: model.received).frame(height: 280).clipShape(
                RoundedRectangle(cornerRadius: 16)
              ).accessibilityLabel("QR code camera")
            } else {
              Text("Camera unavailable. Use setup JSON or manual attendee lookup.")
            }
            if model.setup == nil {
              TextEditor(text: $model.setupText).frame(height: 120).autocorrectionDisabled()
                .textInputAutocapitalization(.never).accessibilityLabel("Staff setup JSON")
              Button("Install staff setup") { model.installSetup(model.setupText) }.buttonStyle(
                .borderedProminent)
            } else {
              HStack {
                TextField("Find attendee by name", text: $model.lookupText)
                Button("Search") { Task { await model.lookup() } }
              }
              ForEach(Array(model.matches.enumerated()), id: \.offset) { _, ticket in
                Button(ticket["display_name"]?.string ?? "Attendee") {
                  Task { await model.manual(ticket) }
                }.buttonStyle(.bordered)
              }
            }
          }
        }.padding()
      }.navigationTitle("GatePass")
    }
  }
}

struct QRScanner: UIViewControllerRepresentable {
  let onCode: (String) -> Void
  func makeUIViewController(context: Context) -> CameraController {
    CameraController(onCode: onCode)
  }
  func updateUIViewController(_ controller: CameraController, context: Context) {}
}

final class CameraController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
  private let session = AVCaptureSession()
  private let sessionQueue = DispatchQueue(
    label: "dev.rohanshinde24.gatepass.camera", qos: .userInitiated)
  private let onCode: (String) -> Void
  private var preview: AVCaptureVideoPreviewLayer?
  init(onCode: @escaping (String) -> Void) {
    self.onCode = onCode
    super.init(nibName: nil, bundle: nil)
  }
  required init?(coder: NSCoder) { fatalError("Not supported") }
  override func viewDidLoad() {
    super.viewDidLoad()
    guard let camera = AVCaptureDevice.default(for: .video),
      let input = try? AVCaptureDeviceInput(device: camera), session.canAddInput(input)
    else { return }
    session.addInput(input)
    let output = AVCaptureMetadataOutput()
    guard session.canAddOutput(output) else { return }
    session.addOutput(output)
    output.setMetadataObjectsDelegate(self, queue: .main)
    output.metadataObjectTypes = [.qr]
    let preview = AVCaptureVideoPreviewLayer(session: session)
    preview.videoGravity = .resizeAspectFill
    view.layer.addSublayer(preview)
    self.preview = preview
    sessionQueue.async { [session] in session.startRunning() }
  }
  override func viewDidLayoutSubviews() {
    super.viewDidLayoutSubviews()
    preview?.frame = view.bounds
  }
  override func viewDidDisappear(_ animated: Bool) {
    super.viewDidDisappear(animated)
    sessionQueue.async { [session] in session.stopRunning() }
  }
  func metadataOutput(
    _ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject],
    from connection: AVCaptureConnection
  ) {
    guard let value = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue else {
      return
    }
    onCode(value)
  }
}

enum SetupKeychain {
  private static let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "dev.rohanshinde24.gatepass", kSecAttrAccount as String: "scanner",
  ]
  static func save(_ value: Data) throws {
    let update = SecItemUpdate(
      query as CFDictionary, [kSecValueData as String: value] as CFDictionary)
    if update == errSecItemNotFound {
      var item = query
      item[kSecValueData as String] = value
      item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
        throw GatePassError("Could not save staff credentials")
      }
    } else if update != errSecSuccess {
      throw GatePassError("Could not save staff credentials")
    }
  }
  static func read() throws -> Data? {
    var lookup = query
    lookup[kSecReturnData as String] = true
    lookup[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(lookup as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else { throw GatePassError("Could not read staff credentials") }
    return result as? Data
  }
}

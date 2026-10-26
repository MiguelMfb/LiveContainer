import Foundation
import Testing
@testable import SideSign

private final class FixtureState: @unchecked Sendable {
    private let lock = NSLock()
    private var statuses: [Int] = []
    private var captured: [URLRequest] = []

    func reset(_ statuses: [Int]) {
        lock.withLock { self.statuses = statuses; captured = [] }
    }

    func next(_ request: URLRequest) -> Int {
        lock.withLock {
            captured.append(request)
            return statuses.isEmpty ? 200 : statuses.removeFirst()
        }
    }

    var requests: [URLRequest] { lock.withLock { captured } }
}

private final class LoginFixProtocol: URLProtocol, @unchecked Sendable {
    static let fixture = FixtureState()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let status = Self.fixture.next(request)
        let body = status == 200
            ? Data("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>Response</key><dict><key>Status</key><dict><key>ec</key><integer>0</integer></dict></dict></dict></plist>".utf8)
            : Data("<html>Service unavailable</html>".utf8)
        let response = HTTPURLResponse(url: request.url!, statusCode: status,
                                       httpVersion: "HTTP/1.1", headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@Suite(.serialized)
struct LoginFixTests {
    private func portal() -> DeveloperPortal {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [LoginFixProtocol.self]
        return DeveloperPortal(session: URLSession(configuration: config))
    }

    private var anisette: AnisetteData {
        AnisetteData(machineID: "fixture-machine", oneTimePassword: "fixture-otp",
                     localUserID: "fixture-local-user", routingInfo: "17106176",
                     deviceID: "00000000-0000-0000-0000-000000000000",
                     serialNumber: "fixture-serial",
                     clientInfo: "<MacBookPro9,2> <macOS;10.12;16A323> <com.apple.AuthKit/1>",
                     userAgent: "akd/1.0 CFNetwork/808.1.4",
                     clientTime: "2026-10-26T00:00:00Z", locale: "en_US", timeZone: "UTC")
    }

    @Test func currentMacIdentity() async throws {
        LoginFixProtocol.fixture.reset([200])
        _ = try await portal().sendAuthenticationRequest(parameters: ["o": "init"], anisetteData: anisette)
        let request = try #require(LoginFixProtocol.fixture.requests.first)
        #expect(request.value(forHTTPHeaderField: "X-Mme-Client-Info") ==
                "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>")
        #expect(request.value(forHTTPHeaderField: "User-Agent") == "akd/1.0 CFNetwork/808.1.4")
        #expect(request.httpMethod == "POST")
    }

    @Test func rateLimitedRequestRecovers() async throws {
        LoginFixProtocol.fixture.reset([429, 200])
        _ = try await portal().sendAuthenticationRequest(parameters: ["o": "init"], anisetteData: anisette)
        #expect(LoginFixProtocol.fixture.requests.count == 2)
    }

    @Test func unavailableServiceStopsAfterThreeAttempts() async throws {
        LoginFixProtocol.fixture.reset([503, 503, 503, 200])
        var rejected = false
        do {
            _ = try await portal().sendAuthenticationRequest(parameters: ["o": "init"], anisetteData: anisette)
        } catch { rejected = true }
        #expect(rejected)
        #expect(LoginFixProtocol.fixture.requests.count == 3)
    }

    @Test func forbiddenResponseIsNotRepeated() async throws {
        LoginFixProtocol.fixture.reset([403, 200])
        do {
            _ = try await portal().sendAuthenticationRequest(parameters: ["o": "init"], anisetteData: anisette)
        } catch {}
        #expect(LoginFixProtocol.fixture.requests.count == 1)
    }
}

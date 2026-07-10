import Foundation

struct TracerouteHop: Codable {
    let hop: Int
    let ip: String
    let ms: String
    let lost: Bool
}

func withSockAddr<T>(_ addr: inout sockaddr_in, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
    return withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
            body(sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
}

func withMutSockAddr<T>(_ addr: inout sockaddr_in, _ body: (UnsafeMutablePointer<sockaddr>, inout socklen_t) -> T) -> T {
    return withUnsafeMutablePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            return body(sockPtr, &len)
        }
    }
}

func runTraceroute(target: String, maxHops: Int = 30, probeTimeout: TimeInterval = 3) -> [TracerouteHop] {
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)

    let raw = inet_addr(target)
    if raw != INADDR_NONE {
        addr.sin_addr = in_addr(s_addr: raw)
    } else {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(target, nil, &hints, &res) == 0, let r = res else { return [] }
        defer { freeaddrinfo(res) }
        let sin = r.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        addr.sin_addr = sin.sin_addr
    }
    addr.sin_port = CFSwapInt16HostToBig(443)

    let icmpFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
    guard icmpFd >= 0 else { return [] }
    defer { close(icmpFd) }

    var tv = timeval(tv_sec: Int(probeTimeout), tv_usec: 0)
    setsockopt(icmpFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

    let probeFd = socket(AF_INET, SOCK_DGRAM, 0)
    guard probeFd >= 0 else { return [] }
    defer { close(probeFd) }

    var hops: [TracerouteHop] = []
    var destReached = false

    for ttl in 1...maxHops where !destReached {
        var ttlVal = CInt(ttl)
        setsockopt(probeFd, IPPROTO_IP, IP_TTL, &ttlVal, socklen_t(MemoryLayout<CInt>.size))

        var destAddr = addr
        let probePort = UInt16(33434 + ttl)
        destAddr.sin_port = CFSwapInt16HostToBig(probePort)

        let start = Date()

        let sent = withSockAddr(&destAddr) { sa, len in
            sendto(probeFd, "", 0, 0, sa, len)
        }
        guard sent >= 0 else {
            hops.append(TracerouteHop(hop: ttl, ip: "*", ms: "", lost: true))
            continue
        }

        var fromAddr = sockaddr_in()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        var buf = [UInt8](repeating: 0, count: 512)
        let n = withUnsafeMutablePointer(to: &fromAddr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                recvfrom(icmpFd, &buf, 512, 0, sockPtr, &fromLen)
            }
        }

        let elapsed = Date().timeIntervalSince(start)

        if n >= 8 {
            let type = buf[0]
            let code = buf[1]

            let hopIP = String(cString: inet_ntoa(fromAddr.sin_addr))
            let ms = String(format: "%.1f", elapsed * 1000)

            if type == 11 && code == 0 {
                hops.append(TracerouteHop(hop: ttl, ip: hopIP, ms: ms, lost: false))
            } else if type == 3 {
                hops.append(TracerouteHop(hop: ttl, ip: hopIP, ms: ms, lost: false))
                destReached = true
            } else {
                hops.append(TracerouteHop(hop: ttl, ip: "*", ms: "", lost: true))
            }
        } else {
            hops.append(TracerouteHop(hop: ttl, ip: "*", ms: "", lost: true))
        }
    }

    return hops
}

func startTracerouteService() {
    DispatchQueue.global(qos: .background).async {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return }
        defer { close(sock) }

        var val: CInt = 1
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, socklen_t(MemoryLayout<CInt>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_addr = in_addr(s_addr: INADDR_LOOPBACK)
        addr.sin_port = CFSwapInt16HostToBig(8091)

        let bindOK = withSockAddr(&addr) { sa, len in
            bind(sock, sa, len) == 0
        }
        guard bindOK else { return }
        guard listen(sock, 5) == 0 else { return }

        while true {
            var clientAddr = sockaddr_in()
            var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let client = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    accept(sock, sockPtr, &clientLen)
                }
            }
            guard client >= 0 else { continue }

            DispatchQueue.global(qos: .background).async {
                handleClient(client)
                close(client)
            }
        }
    }
}

private func handleClient(_ client: CInt) {
    var buf = [UInt8](repeating: 0, count: 2048)
    let n = read(client, &buf, 2048)
    guard n > 0 else { return }

    let request = String(cString: buf)
    guard let (method, path) = parseHTTPRequest(request) else { return }

    if method == "GET" && path.hasPrefix("/traceroute/") {
        let ip = String(path.dropFirst("/traceroute/".count))
        guard !ip.isEmpty else {
            sendResponse(client, status: 400, body: "missing ip")
            return
        }
        let hops = runTraceroute(target: ip)
        let encoder = JSONEncoder()
        if let data = try? encoder.encode(hops) {
            sendResponse(client, status: 200, body: String(data: data, encoding: .utf8) ?? "[]")
        } else {
            sendResponse(client, status: 200, body: "[]")
        }
    } else if method == "GET" && path == "/health" {
        sendResponse(client, status: 200, body: "{\"status\":\"ok\"}")
    } else {
        sendResponse(client, status: 404, body: "not found")
    }
}

private func parseHTTPRequest(_ raw: String) -> (String, String)? {
    let parts = raw.components(separatedBy: " ")
    guard parts.count >= 2 else { return nil }
    return (parts[0], parts[1])
}

private func sendResponse(_ client: CInt, status: Int, body: String) {
    let statusText = status == 200 ? "OK" : (status == 400 ? "Bad Request" : "Not Found")
    let resp = "HTTP/1.1 \(status) \(statusText)\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
    resp.withCString { ptr in
        write(client, ptr, strlen(ptr))
    }
}
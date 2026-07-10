import Foundation

struct TracerouteHop: Codable {
    let hop: Int
    let ip: String
    let ms: String
    let lost: Bool
}

func runTraceroute(target: String, maxHops: Int = 30, probeTimeout: TimeInterval = 3) -> [TracerouteHop] {
    if target.contains(":") {
        return runTracerouteV6(target: target, maxHops: maxHops, probeTimeout: probeTimeout)
    }
    return runTracerouteV4(target: target, maxHops: maxHops, probeTimeout: probeTimeout)
}

// MARK: - IPv4

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

func runTracerouteV4(target: String, maxHops: Int = 30, probeTimeout: TimeInterval = 3) -> [TracerouteHop] {
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

// MARK: - IPv6

func runTracerouteV6(target: String, maxHops: Int = 30, probeTimeout: TimeInterval = 3) -> [TracerouteHop] {
    var addr = sockaddr_in6()
    addr.sin6_family = sa_family_t(AF_INET6)

    var hints = addrinfo()
    hints.ai_family = AF_INET6
    hints.ai_socktype = SOCK_DGRAM
    var res: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(target, nil, &hints, &res) == 0, let r = res else { return [] }
    defer { freeaddrinfo(res) }
    let sin6 = r.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
    addr.sin6_addr = sin6.sin6_addr
    addr.sin6_port = CFSwapInt16HostToBig(33434)

    let icmpFd = socket(AF_INET6, SOCK_DGRAM, 58)
    guard icmpFd >= 0 else { return [] }
    defer { close(icmpFd) }

    var tv = timeval(tv_sec: Int(probeTimeout), tv_usec: 0)
    setsockopt(icmpFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

    let probeFd = socket(AF_INET6, SOCK_DGRAM, 0)
    guard probeFd >= 0 else { return [] }
    defer { close(probeFd) }

    var hops: [TracerouteHop] = []
    var destReached = false

    for ttl in 1...maxHops where !destReached {
        var ttlVal = CInt(ttl)
        setsockopt(probeFd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttlVal, socklen_t(MemoryLayout<CInt>.size))

        var destAddr = addr
        destAddr.sin6_port = CFSwapInt16HostToBig(UInt16(33434 + ttl))

        let start = Date()

        let sent = withSockAddrV6(&destAddr) { sa, len in
            sendto(probeFd, "", 0, 0, sa, len)
        }
        guard sent >= 0 else {
            hops.append(TracerouteHop(hop: ttl, ip: "*", ms: "", lost: true))
            continue
        }

        var fromAddr = sockaddr_in6()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in6>.size)
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

            var ipBuf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            var sin6Addr = fromAddr.sin6_addr
            inet_ntop(AF_INET6, &sin6Addr, &ipBuf, socklen_t(INET6_ADDRSTRLEN))
            let hopIP = String(cString: ipBuf)
            let ms = String(format: "%.1f", elapsed * 1000)

            // ICMPv6: type 3=Time Exceeded(code 0=hop limit), type 1=Unreachable
            if type == 3 && code == 0 {
                hops.append(TracerouteHop(hop: ttl, ip: hopIP, ms: ms, lost: false))
            } else if type == 1 {
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

func withSockAddrV6<T>(_ addr: inout sockaddr_in6, _ body: (UnsafePointer<sockaddr>, socklen_t) -> T) -> T {
    return withUnsafePointer(to: &addr) { ptr in
        ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
            body(sockPtr, socklen_t(MemoryLayout<sockaddr_in6>.size))
        }
    }
}

// MARK: - HTTP Server

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

        let bindResult = withSockAddr(&addr) { sa, len in
            bind(sock, sa, len)
        }
        guard bindResult >= 0 else { return }

        listen(sock, 5)

        while true {
            var clientAddr = sockaddr_in()
            var clientLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let client = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    accept(sock, sockPtr, &clientLen)
                }
            }
            guard client >= 0 else { continue }
            defer { close(client) }

            var buf = [UInt8](repeating: 0, count: 4096)
            let n = read(client, &buf, 4096)
            guard n > 0 else { continue }

            let request = String(cString: buf)
            let lines = request.components(separatedBy: "\r\n")
            guard let firstLine = lines.first else { continue }
            let parts = firstLine.components(separatedBy: " ")
            guard parts.count >= 2 else { continue }
            let method = parts[0]
            let path = parts[1]

            if method == "GET" && path.hasPrefix("/traceroute/") {
                let ip = String(path.dropFirst("/traceroute/".count))
                let hops = runTraceroute(target: ip)
                if let data = try? JSONEncoder().encode(hops) {
                    let body = String(data: data, encoding: .utf8) ?? "[]"
                    let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
                    write(client, response, response.utf8.count)
                } else {
                    let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    write(client, response, response.utf8.count)
                }
            } else {
                let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                write(client, response, response.utf8.count)
            }
        }
    }
}
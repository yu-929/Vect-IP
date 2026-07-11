import SwiftUI
import WebKit
import UserNotifications

struct WebView: UIViewRepresentable {
    let url: URL

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        let userContent = WKUserContentController()
        userContent.add(context.coordinator, name: "vectNotify")
        let bridgeJS = """
        window.vectNotify = function(data) {
            window.webkit.messageHandlers.vectNotify.postMessage(data);
        };
        """
        let script = WKUserScript(source: bridgeJS, injectionTime: .atDocumentStart, forMainFrameOnly: false)
        userContent.addUserScript(script)
        config.userContentController = userContent
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.scrollView.bounces = false
        tryLoad(webView, url: url, coordinator: context.coordinator)
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
    }

    private func tryLoad(_ webView: WKWebView, url: URL, coordinator: Coordinator) {
        let request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 3)
        webView.load(request)
    }

    class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        private var retryCount = 0
        private let maxRetries = 10
        private let retryDelay: UInt64 = 500_000_000

        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            if message.name == "vectNotify", let body = message.body as? [String: String] {
                let title = body["title"] ?? "Vect"
                let msgBody = body["body"] ?? ""
                let content = UNMutableNotificationContent()
                content.title = title
                content.body = msgBody
                content.sound = .default
                let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
                UNUserNotificationCenter.current().add(request)
            }
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            let nsError = error as NSError
            if nsError.domain == NSURLErrorDomain,
               (nsError.code == NSURLErrorCannotConnectToHost || nsError.code == NSURLErrorDNSLookupFailed || nsError.code == NSURLErrorTimedOut),
               retryCount < maxRetries {
                retryCount += 1
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak webView] in
                    guard let wv = webView else { return }
                    wv.load(URLRequest(url: URL(string: "http://127.0.0.1:8080")!,
                                       cachePolicy: .reloadIgnoringLocalAndRemoteCacheData,
                                       timeoutInterval: 3))
                }
            } else if retryCount >= maxRetries {
                let retryHTML = """
                <html><body style="display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;font-family:-apple-system;background:#0F1118;color:#e2e8f0;text-align:center;padding:24px">
                <div style="font-size:48px;margin-bottom:16px">&#9888;</div>
                <h2 style="color:#FF5F57;margin-bottom:8px">服务器启动失败</h2>
                <p style="color:#94a3b8;margin-bottom:20px;font-size:14px">\(error.localizedDescription)</p>
                <button onclick="location.reload()" style="background:#4294FF;color:#fff;border:none;border-radius:12px;padding:12px 32px;font-size:16px;font-weight:600;cursor:pointer">重试</button>
                </body></html>
                """
                webView.loadHTMLString(retryHTML, baseURL: nil)
            }
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            retryCount = 0
        }
    }
}
import SwiftUI
import WebKit

struct WebView: UIViewRepresentable {
    let url: URL

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.scrollView.bounces = false
        let request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData)
        webView.load(request)
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
    }

    class Coordinator: NSObject, WKNavigationDelegate {
        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            let errorHTML = """
            <html><body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:-apple-system;background:#0f172a;color:#e2e8f0;text-align:center">
            <div>
            <h2 style="color:#ef4444">连接失败</h2>
            <p style="color:#94a3b8">\(error.localizedDescription)</p>
            <p style="color:#64748b;font-size:12px">请在设置中检查服务器地址</p>
            </div></body></html>
            """
            webView.loadHTMLString(errorHTML, baseURL: nil)
        }
    }
}
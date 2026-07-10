import SwiftUI

class AppSettings: ObservableObject {
    let serverURL: URL

    init() {
        serverURL = URL(string: "http://127.0.0.1:8080")!
    }
}
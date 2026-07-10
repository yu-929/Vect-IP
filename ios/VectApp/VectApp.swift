import SwiftUI

@main
struct VectApp: App {
    @StateObject private var settings = AppSettings()

    init() {
        startTracerouteService()
        let ret = StartVectServer(8080)
        if ret != 0 {
            print("Failed to start Vect server")
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(settings)
        }
    }
}
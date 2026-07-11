import SwiftUI
import UserNotifications

@main
struct VectApp: App {
    @StateObject private var settings = AppSettings()

    init() {
        startTracerouteService()
        let ret = StartVectServer(8080)
        if ret != 0 {
            print("Failed to start Vect server")
        }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            if granted { print("Notification permission granted") }
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(settings)
        }
    }
}
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var settings: AppSettings

    var body: some View {
        WebView(url: settings.serverURL)
            .ignoresSafeArea(.all)
    }
}
import SwiftUI

struct SettingsView: View {
    var body: some View {
        Form {
            Section("说明") {
                Text("Vect IP 优选器运行在 iPhone 本地")
                Text("扫描引擎和 Web 服务已内嵌到 App 中")
                Text("不需要外部服务器，开箱即用")
            }
            Section("注意") {
                Text("CIDR 扫描需要网络权限")
                Text("扫描过程可能消耗流量和电量")
            }
        }
        .navigationTitle("关于")
    }
}
# GocryptKit

在 macOS 上原生挂载 [gocryptfs](https://github.com/rfjakob/gocryptfs) 加密卷，基于 Apple 现代原生 **FSKit** 框架。

**零 kext、零 macFUSE、零 sudo、零安全降级** —— SIP 保持开启，无需 Reduced Security，无需 FUSE-T。

[English Documentation (README in English)](README.md)

---

## 特性与优势

- **Apple 原生深度融合**：基于 macOS FSKit 用户态文件系统架构，卷可直接在 Finder、终端及各类文件选择器中无缝读写。
- **高安全凭据机制**：
  - 采用严格 TLV Tagged Keychain 协议（即用即焚，挂载后立即物理销毁凭据）。
  - 内存安全擦除：在 C/Swift 边界对 MasterKey、用户密码及 Scrypt 缓冲区强制调用 `memset_s` 清零，杜绝密码落盘或遗留 Core Dump。
  - 命令行严禁明文暴露口令：彻底移除 `--password <明文>` 参数，采用交互式无回显终端输入或标准管道输入 `--password-stdin`。
- **并发句柄读写物理隔离**：读、写文件描述符物理分离并配备读写锁，根除多线程高并发读写竞争引发的内核 `EBADF`。
- **原生扩展属性 (xattr)**：基于 EME+DirIV 加密，全面支持 macOS 标签与元数据，防止系统产生 `._*` AppleDouble 垃圾文件。
- **状态栏与交互体验增强**：
  - 菜单栏常驻图标随挂载状态动态反馈（挂载时切换为开锁形态 `lock.open.fill`）。
  - 卸载防重置灰与互锁机制，避免连击导致系统扩展死锁。
  - 批量卸载多卷遇阻（`EBUSY`）时自动合并弹窗集中告警，支持一键全部强制卸载。
- **纯粹优雅的 SwiftUI 客户端**：支持快速新建加密卷或添加已有卷，实时同步内核挂载表（`getfsstat`）。

---

## 下载与体验

**v1.2.5** — 质量加固、安全性与易用性提升版本（macOS Apple Silicon）

→ [前往 GitHub Releases 页面下载](https://github.com/maxing-labs/GocryptKit/releases/tag/v1.2.5)

| 项 | 值 |
|---|---|
| 文件 | `GocryptKit-1.2.5.dmg` |
| 架构 | Apple Silicon (`arm64-only`) |
| 签名 | Developer ID Application（已通过苹果官方公证 Notarized & Stapled） |

校验 DMG 安装包：

```bash
shasum -a 256 GocryptKit-1.2.5.dmg
spctl -a -t open --context context:primary-signature -vv GocryptKit-1.2.5.dmg
```

安装步骤见下面的[安装后第一次使用](#安装后第一次使用)。

---

## 安装后第一次使用

1. 把 `GocryptKit.app` 拖进「应用程序」(`/Applications`)；
2. 打开一次 App；
3. **系统设置 → 通用 → 登录项与扩展 → 滚动到最底部点「文件系统扩展（按类别）」→ 打开 GocryptKit 开关**；
4. 在 App 里点「添加已有 Vault…」选中密文目录，或点「创建新 Vault…」初始化空目录；
5. 输入密码，点「挂载」，解密后的卷即刻出现在 Finder 侧边栏。

### 命令行工具使用 (CLI)

App 二进制内置了完备的 CLI 接口：

```bash
# 交互式安全创建新卷 (密码终端无回显)
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit init <空目录>

# 脚本自动化创建 (通过 stdin 传递密码)
echo "your-password" | /Applications/GocryptKit.app/Contents/MacOS/GocryptKit init <空目录> --password-stdin

# 挂载卷
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit mount <密文目录> <挂载点>

# 卸载卷
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit umount <挂载点>

# 检查 FSKit 扩展状态
/Applications/GocryptKit.app/Contents/MacOS/GocryptKit status
```

> ⚠️ **安全警告**：出于安全考虑，CLI **已彻底废除 `--password <明文>` 命令行参数**，防止密码泄露在 `ps` 进程表或 Shell 历史记录中。自动化脚本请统一采用 `--password-stdin` 管道传参。

---

## 环境要求与源码构建

### 环境要求

- macOS 26.0+（Apple Silicon，发行版本为 arm64-only）
- 构建工具：Xcode 26+、Go 1.25+、[XcodeGen](https://github.com/yonaskolb/XcodeGen)、`create-dmg`
- 测试工具：`ffmpeg`（含 libmp3lame / libx264）

### 源码构建步骤

```bash
git clone https://github.com/maxing-labs/GocryptKit.git
cd GocryptKit

# 1. 编译 Go 核心引擎 (darwin arm64 c-archive)
Engine/build-darwin.sh

# 2. 封装为 xcframework
Engine/make-xcframework.sh

# 3. 生成 Xcode 工程 (project.yml -> GocryptKit.xcodeproj)
xcodegen generate

# 4. 编译 Release 版本
xcodebuild -project GocryptKit.xcodeproj -scheme GocryptKit \
  -configuration Release build
```

> **外部开发者提示**：  
> `project.yml` 默认配置了维护者发布配置。若在本地使用自己的 Apple ID 调试，可将 `project.yml` 中的 `DEVELOPMENT_TEAM` 替换为你自己的 Team ID，或在 Xcode 中勾选个人签名证书即可。

### 打包 DMG

项目提供了一键打包脚本：

```bash
Scripts/build-dmg.sh
```

产物将输出至 `build/dist/GocryptKit-1.2.5.dmg`。

---

## 测试

```bash
# 运行 VaultCore 单元测试套件 (95 项断言，含加密与 TLV 凭据协议验证)
swift test --package-path Packages/VaultCore

# 运行端到端验收脚本 (需先安装 App 并在系统设置中启用扩展)
Tests/e2e/make-samples.sh
Tests/e2e/run-e2e.sh
```

---

## 开源许可证

本项目采用 [GNU General Public License v3.0 (GPL-3.0)](LICENSE) 授权许可（附带 Apple App Store 例外授权条款）。

底层核心引擎 `Engine/libgocryptfs` 基于 upstream [gocryptfs](https://github.com/rfjakob/gocryptfs)，遵循 MIT 协议。

### 素材致谢

App 图标里的「文件夹 + 钥匙」字形来自 [Flaticon](https://www.flaticon.com/free-icon/folder_10303679)（素材 ID `10303679`），遵循 Flaticon Free License 使用。详细许可说明见 [`Art/ATTRIBUTION.md`](Art/ATTRIBUTION.md)。

<p align="center">
  <img src="Art/AppIcon.png" width="128" height="128" alt="GocryptKit 图标">
</p>

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

**v1.3.8** — 架构健壮性、UI 预检与事件驱动同步最终版（macOS Apple Silicon）

→ [前往 GitHub Releases 页面下载](https://github.com/maxing-labs/GocryptKit/releases/tag/v1.3.8)

| 项 | 值 |
|---|---|
| 文件 | `GocryptKit-1.3.8.dmg` |
| 架构 | Apple Silicon (`arm64-only`) |
| 签名 | Developer ID Application（已通过苹果官方公证 Notarized & Stapled） |

校验 DMG 安装包：

```bash
shasum -a 256 GocryptKit-1.3.8.dmg
spctl -a -t open --context context:primary-signature -vv GocryptKit-1.3.8.dmg
```

安装步骤见下面的[安装后第一次使用](#安装后第一次使用)。

---

## 版本更新历史 (What's New)

### v1.3.8 (2026-09-19) — 架构健壮性与深度测试
- **挂载点预检预警**：在未挂载状态下，展开卡片实时探测挂载点路径，若目标目录已存在且非空，给予非侵入式浅色提醒，避免挂载失败。
- **卡片布局优化与 Switch 增强**：挂载模式 Switch 开关左侧补充“可写”状态标签，且将高频关心的“挂载点”移至“加密目录”上方，信息层级更清晰。
- **类型化错误模型**：在 `VaultCore` 中将挂载与卸载错误封装为强类型的 `MountError` 与 `UnmountError`，彻底告别脆弱的字符串包含判断。
- **双模事件驱动状态同步**：接入 `NSWorkspace` 的 `didMountNotification` 和 `didUnmountNotification` 系统通知，Finder 弹出/挂载实现毫秒级即时响应，保留 2 秒轮询作为 CLI 兜底。
- **CLI 增强**：`GocryptKit umount` 支持 `-f` / `--force` 强制卸载参数。
- **0 字节空文件读取修复**：Go 引擎在读取空文件时直接返回 0 (EOF)，修复原本由于缺乏 Header 抛出 `EIO` 的边缘问题。
- **完备鲁棒性测试**：新增 `RobustnessTests` 覆盖块边界（0B、4096B、4097B）、8 线程并发读写、密文篡改/位翻转校验拦截等场景（108/108 用例通过）。

### v1.3.7 (2026-09-19) — 卸载可靠性与 UI 交互增强版
- **卸载可靠性与交互对齐**：
  - **宗卷占用弹窗与强制卸载**：彻底修复主界面折叠状态下卸载被占用宗卷时“转圈 1 秒无反应”问题。当加密卷文件正被其他 App（如播放器、访达或终端）打开时，主界面卸载会立即弹出原生警告对话框，提供“强制卸载”快捷操作，与菜单栏托盘行为 100% 对齐；
  - **异常时自动展开**：卸载遇阻或取消后，卡片自动展开并就地高亮错误诊断与“强制卸载…”按钮，确保用户随时获知状态；
  - **挂载路径回退兜底**：加固挂载点路径解析，自动探测只读后缀（`_READ_ONLY`）与内核实时挂载表，杜绝因路径漂移导致的卸载失败。
- **UI 布局优化**：
  - **挂载模式 Switch 开关升级**：将原先易引起语义歧义的“仅本次临时只读”复选框全面重构为直观的原生 Switch 开关。开启（ON）即以读写模式挂载，关闭（OFF）即以只读模式挂载，带有动态警示橙色与挂载按钮/路径预览实时联动；
  - **密码错误提示就地呈现**：修复解锁失败（密码或主密钥错误）时提示文字被甩在卡片最底部的视觉缺陷。错误提示现直接在密码输入框下方就地高亮呈现，且在用户修改密码时自动清除；
  - **“名称”输入框移至底部**：将低频重命名操作下移至卡片最底部，突显高频的密码挂载与路径信息。

### v1.3.6 (2026-09-19) — UI 交互优化与多语言体验版
- **UI 交互优化**：
  - **展开卡片密码框置顶**：将密码输入框、挂载按钮与临时只读复选框移至展开卡片最顶端，展开时第一时间聚焦密码输入；
  - **“名称”输入框移至底部**：将日常低频使用的卷“名称”重命名输入框下移至详情最底部，使视觉重心完全集中于挂载与路径；
  - **移除卡片键盘焦点蓝框**：彻底移除卷卡片外层键盘获焦高亮蓝框，恢复原生简洁分割边框。
- **本地化修复**：
  - 修复大写锁定（Caps Lock）状态提示气泡偶发 `localized string not found` 问题，完善 `AppleLanguages` 包含 `zh-CN` 与 `en` 的回退链条，并在工程中配置 `CFBundleLocalizations`；
  - 补齐密码最少 4 字符静态校验及大写锁定状态本地化词条。
- **构建与质量**：
  - Apple 官方签名与公证装订 DMG（`GocryptKit-1.3.6.dmg`），104 项单元测试与 108 项端到端（E2E）验收全绿。

### v1.3.5 (2026-09-19) — 质量加固、并发可靠性与安全正式版
- **安全加固**：
  - 新建卷弱密码二次强警告确认弹窗（<8 字符或强度较弱），在兼顾弹性密码策略的同时严防误设弱口令；
  - `OrphanReaper` 孤儿凭据清扫扩展支持只读会话临时凭据（`mountctx:`），在应用退出与启动时深度扫除；
  - 彻底移除 `KeychainHelper` 与 `KeychainReader` 冗余 Facade，全工程直接统一定位 `VaultCore.KeychainStore`。
- **并发与防管道死锁**：
  - 引入 Swift 6 并发安全 `LockedBuffer`，在 `ProcessRunner` 中通过 `readabilityHandler` 异步流式排空子进程 stderr，根除超过 64 KiB 时的操作系统管道死锁；
  - 将 `MountManager` 中重复的超时子进程运行器收敛至 `ProcessRunner`；
  - 将 `MountManager.extensionStatus` 严格收归 `@MainActor` 并增加并发安全的内部辅助属性，杜绝后台轮询与 UI 渲染竞争。
- **体验与本地化**：
  - 只读挂载分级文案明确区分“持久只读配置”与“仅本次临时只读”；
  - 新建加密卷时若父级目录不存在，输入时友好提示并在创建时自动递归建树；
  - macOS 系统顶栏菜单（编辑、窗口、撤销/重做、剪切/复制/粘贴、全选等）全量支持中英文动态本地化；
  - 卷列表卡片支持 `.focusable()` 键盘焦点高亮与空格键（Space）展开折叠。
- **质量验证**：104 项单元测试 + 108 项端到端（E2E）验收全绿，Apple 官方公证与装订。

### v1.3.4 — 多语言冷启动同步与只读拦截回归
- 修复语言切换冷启动偶发不同步问题，确保 App 首选语言与 `AppleLanguages` 实时同步；
- 扩展 E2E 测试链路，严格覆盖只读卷内核级写入拦截（touch/mkdir/append/rename/chmod/rm）。

### v1.3.0 – v1.3.3 — 只读 Finder 显示与打包流水线优化
- 通过共享 Keychain 挂载意图上下文（`MountContextStore`），确保只读卷在 Finder 窗口标题和侧边栏准确显示 `_READ_ONLY` 后缀；
- 健壮解析 FSKit 复合挂载参数（`ro`, `rdonly`, `volname`）；
- 优化发布流水线，增加公证超时自动重试与 `create-dmg` 无窗口模式降级。

### v1.2.5 — 纵深防御与安全卸载
- 在 App 退出阶段增加防御性强制卸载（`umount -f`）兜底机制，杜绝卷残留；
- 在标准「关于」面板中补充开源仓库与技术文档直达链接。

### v1.2.4 — 首个正式开源发布版
- 正式在 GitHub 开源（[maxing-labs/GocryptKit](https://github.com/maxing-labs/GocryptKit)），采用 GPL-3.0 附带 Apple App Store 商业例外授权；
- 状态栏增强：增加卸载防重置灰、并发互锁，以及批量卸载遭遇 `EBUSY` 时的集中合并告警；
- 密码策略由强制阻断优化为弹性告警角标；
- 全工程代码注释英文化重构。

### v1.2.0 — 架构解耦与审查整改
- 针对代码审查意见重构核心模块，增强代码分层与职责分离。

### v1.1.2 — 媒体 Seek 修复与退出拦截
- 底层 Go C-API 实现分块循环读取（Chunked Read Loop），根除大视频文件随机 Seek 与 Python `pread` 报 `EIO`（输入输出错误）的问题；
- 读写底层文件描述符彻底物理分离，独立引用计数与读写锁；
- 新增 App 退出时拦截挂载卷保护提示；
- 修复卸载时焦点被强行窃取至密码框的体验问题。

### v1.1.0 — 严格 TLV 凭据协议与架构重构
- 引入 VCP1 严格 TLV Tagged 凭据协议，断言长度并丢弃多余残余数据，杜绝密码与 32 字节 Scrypt 哈希类型混淆；
- 视图拆分为 `ContentView`、`VaultRowView`、`VaultRowViewModel` 与 `MountManager`；
- 单元测试增至 90 项。

### v1.0.1 — 菜单栏常驻与自动聚焦
- 新增 MenuBar 状态栏动态开锁图标（`lock.open.fill` / `lock.fill`）；
- 展开卷卡片时密码框自动聚焦；
- 完成大文件高负载读写压测。

### v1.0.0 — 项目更名与闭环里程碑
- 项目正式更名为 `GocryptKit`；
- 打包首个完整公证的 macOS DMG；
- 建立全套安全规范、架构文档（`AGENTS.md`）与开源净化导出流水线。

### v0.2.3 — 深度安全加固版
- 引入 TLV Tagged Keychain 协议与即用即焚销毁机制（`deleteCredential`）；
- 实现平台无关的纯逻辑 `OrphanReaper` 孤儿凭据收割算法；
- 核心敏感内存强制 `memset_s` 清零；
- 废除 `--password` 明文传参，改为无回显输入或 `--password-stdin`；
- 配置注册表强制 `0600` POSIX 权限。

### v0.2.2 — 国际化与界面优化
- 支持中英文双语本地化；
- 增加密码明文/密文切换查看按钮；
- 探索 iOS/iPadOS 原型架构。

### v0.2.1 — 鲁棒性与扩展状态检测修复
- 解耦发布烟囱测试与实时扩展状态依赖；
- 修复在卷已挂载时错误探测 FSKit 模块引发的虚假报错。

### v0.2.0 — 多卷管理与独立图标
- SwiftUI 实现多卷列表与空状态引导；
- 确立「文件夹+钥匙」独立 App 图标设计；
- 采用 `pluginkit` 安全检测扩展注册。

### v0.1.0 — 首个可分发里程碑
- 首个可分发的苹果公证版 DMG；
- 实现原生 FSKit 读写 gocryptfs 卷、宿主 App 与 CLI 工具；
- 确立 Developer ID 内外层自底向上签名流水线与初始 87 项端到端验收用例。

### 早期孵化里程碑 (M0 – M2.5)
- **M2.5**：Host 与 FSKit 扩展间 Keychain 凭据安全通道第一代；CLI 安全改造（废除明文传参，改为无回显输入与管道模式）；中英文双语框架初版。
- **M2**：完整读写文件系统变动（增删改查）；macOS 原生扩展属性（xattr）经 EME+DirIV 加密落盘；`.fseventsd/no_log` 日志抑制。
- **M1.5**：可复现 Developer ID 签名流水线；Apple 官方公证（notarytool）与装订自动化；编写覆盖真实媒体（PDF、MP3、MP4、文本）的端到端集成测试套件。
- **M1**：只读 FSKit 卷核心实现，成功在无需任何驱动或内核扩展的情况下将 gocryptfs 挂载进 Finder。
- **M0.5**：FSKit 模块注册、生命周期管理与文件系统模块（`FSFileSystem`）烟囱打通。
- **M0**：底层 Go 引擎编译（`libgocryptfs` darwin/arm64 c-archive 并打成 `libgocryptfs.xcframework`）、`VaultCore` Swift 核心库骨架与 `vaultctl` 测试命令行。

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
git clone https://github.com/maxing-labs/gocryptfs-kit.git
cd gocryptfs-kit

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

产物将输出至 `build/dist/GocryptKit-1.3.7.dmg`。

---

## 测试

```bash
# 运行 VaultCore 单元测试套件 (104 项断言，含加密、TLV 凭据协议与 OrphanReaper 验证)
swift test --package-path Packages/VaultCore

# 运行端到端验收脚本 (108 项断言，需先安装 App 并在系统设置中启用扩展)
Tests/e2e/make-samples.sh
Tests/e2e/run-e2e.sh
```

---

## 开源许可证

本项目采用 [GNU General Public License v3.0 (GPL-3.0)](LICENSE) 授权许可（附带 Apple App Store 例外授权条款）。

底层核心引擎 `Engine/libgocryptfs` 基于 upstream [gocryptfs](https://github.com/rfjakob/gocryptfs)，遵循 MIT 协议。

### 素材致谢

App 图标里的「文件夹 + 钥匙」字形来自 [Flaticon](https://www.flaticon.com/free-icon/folder_10303679)（素材 ID `10303679`），遵循 Flaticon Free License 使用。详细许可说明见 [`Art/ATTRIBUTION.md`](Art/ATTRIBUTION.md)。

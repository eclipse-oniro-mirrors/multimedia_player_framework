# 模块演进

> 屏幕录制引擎、ScreenCaptureServer 模块、IPC 通信、隐私保护的版本演进记录。

## 一、屏幕录制引擎演进

| 维度 | 说明 |
|------|------|
| 引入版本 | API 10（OH_AVScreenCapture C API） |
| 架构特点 | 无独立引擎层，直接调用 Rosen（显示管理）和 AudioCapturer（音频采集），不同于 AVPlayer 的 EngineFactory + Pipeline 架构 |
| API 12+ | 新增 Strategy 策略配置、Picker 选择器、ContentFilter 内容过滤、Highlight 高亮区域、多屏采集、Pause/Resume、Watermark 等高级特性 |
| 数据模式 | BUFFER_MODE（原始帧缓冲）→ SURFACE_MODE（Surface 直接传递）→ FILE_MODE（Recorder 编码封装） |
| 废弃 | ENCODED_STREAM 数据类型不支持（返回 MSERR_UNSUPPORT） |

## 二、ScreenCaptureServer 模块演进

| 阶段 | 变更内容 |
|------|---------|
| 1. 初始版本 | 基础录屏服务端、7 状态能力位图状态机、IPC Stub/Proxy、主屏/指定窗口模式 |
| 2. 数据模式扩展 | ORIGINAL_STREAM 原始流 + CAPTURE_FILE 文件录制、Surface 模式 |
| 3. 隐私保护机制 | PrivacyProtected 系统级/应用级隐私窗口保护、隐私窗口回调 |
| 4. Picker 选择器 | 系统选择器弹窗、多模式选择、排除选择器窗口 |
| 5. 多屏支持 | 虚拟扩展屏模式、多屏能力查询、区域采集、屏幕连接监听 |
| 6. 通话期间保持 | keepCaptureDuringCall 策略、通话状态监听 |
| 7. 暂停/恢复 | Pause/Resume、enablePause 策略开关、通知栏按钮 |
| 8. 内容过滤 | ExcludeContent（音频内容 + 窗口黑名单）、动态音频过滤 |
| 9. 内容变更通知 | OnCaptureContentChanged 回调、HIDE/VISIBLE/UNAVAILABLE 事件 |
| 10. 高级特性 | 窗口描边高亮、水印、策略配置、旋转控制 |
| 11. 账户与语言 | 账户切换停止录屏、语言切换刷新通知 |

## 三、IPC 通信演进

| 阶段 | 变更内容 |
|------|---------|
| 1. 初始版本 | 基础 IPC Stub/Proxy：Service（采集控制）+ Listener（错误/缓冲/状态回调） |
| 2. Listener 增强 | 新增显示屏选择/内容变更/用户选择/隐私保护回调，共 8 个 |
| 3. Controller IPC | 新增用户选择上报/可配置参数查询/销毁，Picker 用户选择通过 Controller 分发 |
| 4. Monitor IPC | 新增录屏状态查询/系统录制器查询、录屏开始/结束/死亡回调 |
| 5. 服务接口扩展 | 从基础采集控制扩展到 41 个消息码，新增 Strategy/Picker/Highlight/Watermark/Pause/Resume/MultiDisplay 等接口 |
| 6. 异常恢复 | 服务端/客户端死亡检测、SessionManager 死亡监听、通知栏按钮响应 |

## 四、隐私保护演进

| 阶段 | 变更内容 |
|------|---------|
| 1. 基础权限校验 | CAPTURE_SCREEN 权限校验 |
| 2. 授权弹窗 | 隐私授权弹窗、用户 ALLOW/DENY 接收 |
| 3. 免授权权限 | EXEMPT_CAPTURE_SCREEN_AUTHORIZE 免弹窗、Root 用户自动授权 |
| 4. 自定义录屏 | CUSTOM_SCREEN_RECORDING 权限跳过弹窗 |
| 5. 隐私窗口保护 | PrivacyProtected 两层保护、ENTER/EXIT_PRIVATE_SCENE 回调 |
| 6. Picker 用户选择 | 系统选择器、用户选择上报、OnUserSelected 回调 |
| 7. 内容过滤 | 音频内容过滤/窗口黑名单、动态更新 |
| 8. 内容变更通知 | OnCaptureContentChanged 回调 |
| 9. 权限使用记录 | 首实例/末实例机制避免重复记录 |

## 知识关联

- [design-patterns](design-patterns.md) - 设计模式与架构解耦
- [capture-lifecycle](capture-lifecycle.md) - 录屏完整生命周期
- [ipc-communication](ipc-communication.md) - IPC 通信与回调机制
- [privacy-and-permission](privacy-and-permission.md) - 隐私保护与权限机制

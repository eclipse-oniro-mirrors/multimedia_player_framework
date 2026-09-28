# 术语表

> 只说明模型不知道的术语，常识类不要写

## 虚拟屏幕（VirtualScreen）
通过 Rosen ScreenManager 创建的虚拟屏幕，将物理屏幕画面镜像或扩展到 Consumer Surface 上。应用通过 SurfaceBuffer 获取每帧视频数据。虚拟屏幕 ID 决定隐私窗口保护、镜像来源等行为。详见 [capture-implementation](entities/capture-implementation.md)

## 能力位图（Capability bitmask）
ScreenCaptureServer 用 7 状态枚举 + 状态-能力映射数组替代 AVPlayer 的状态类继承体系。每个状态对应一组 Capability 位，`IsState(cap)` 通过位与判断当前状态是否允许某操作，非法操作返回 MSERR_INVALID_OPERATION。详见 [capture-lifecycle](technologies/capture-lifecycle.md) + [service-layer](entities/service-layer.md)

## 隐私窗口保护（PrivacyProtected）
虚拟屏幕可设置跳过系统级/应用级隐私窗口保护。设置后含有隐私属性的窗口在录屏时被跳过（黑屏/遮盖），防止敏感信息泄露。隐私窗口出现/消失时通过 ENTER_PRIVATE_SCENE/EXIT_PRIVATE_SCENE 通知应用。详见 [privacy-and-permission](technologies/privacy-and-permission.md)

## 免授权权限（EXEMPT_CAPTURE_SCREEN_AUTHORIZE）
`ohos.permission.EXEMPT_CAPTURE_SCREEN_AUTHORIZE` 权限，持有该权限的系统应用可跳过隐私授权弹窗直接开始录屏。无此权限的应用需经过 POPUP_WINDOW 状态弹出隐私通知窗口等待用户授权。详见 [privacy-and-permission](technologies/privacy-and-permission.md)

## 数据模式（DataType）
录屏数据输出模式：`ORIGINAL_STREAM`（原始流，应用主动获取每帧数据）、`ENCODED_STREAM`（编码流）、`CAPTURE_FILE`（录制到文件，复用 Recorder 引擎）。不同模式决定采集初始化路径。详见 [capture-lifecycle](technologies/capture-lifecycle.md)

## 采集模式（CaptureMode）
录屏目标选择模式：`CAPTURE_HOME_SCREEN`、`CAPTURE_SPECIFIED_SCREEN`、`CAPTURE_SPECIFIED_WINDOW`、`CAPTURE_VIRTUAL_EXTENDED_SCREEN`、`CAPTURE_SPECIFIED_APP`。决定虚拟屏幕创建方式、镜像来源、窗口过滤策略。详见 [capture-lifecycle](technologies/capture-lifecycle.md)

## Picker 选择器
系统级 UI 扩展能力，让用户在录屏开始前选择录制目标（窗口/屏幕/应用）。用户选择后通过 Controller 服务上报结果。`PickerMode` 控制可选目标类型组合。详见 [ipc-communication](technologies/ipc-communication.md) + [monitor-and-controller](entities/monitor-and-controller.md)

## 音频混音（AudioDataSource MixAudio）
AudioDataSource 持有内录和麦克风两路音频采集器，将两路 PCM 数据按时间戳对齐混合后输出。视频首帧 pts 与音频首帧 pts 对齐实现音视频同步。Pause/Resume 时记录 pauseDuration 补偿时间戳偏移。详见 [av-sync-and-buffer](technologies/av-sync-and-buffer.md)

## 缓冲消费者监听器（ScreenCapBufferConsumerListener）
注册到虚拟屏幕 Consumer Surface 的缓冲监听器，监听缓冲就绪回调。内部维护独立线程循环获取 SurfaceBuffer 并回调给应用。Start/Stop/Release 控制线程生命周期。详见 [capture-implementation](entities/capture-implementation.md)

## 会话管理器（ScreenCaptureServerManager）
管理 ScreenCaptureServer 实例生命周期，限制最大实例数和单 UID 最大会话数。超限时拒绝创建并返回错误。负责 SA 注册、实例索引、进程死亡清理。详见 [service-layer](entities/service-layer.md)

## 监听器管理器（ScreenCaptureListenerManager）
统一注册/注销窗口生命周期、窗口信息变更、隐私窗口、屏幕连接、语言切换、账号切换、通话状态、音频渲染器状态、应用生命周期等系统监听器。通过 ListenerFlag 位图按需注册，避免每个实例重复注册。详见 [service-layer](entities/service-layer.md)

## Monitor 单例（ScreenCaptureMonitorServer）
进程级单例，追踪当前所有录屏进程状态。提供查询录屏进程 PID 列表、判断系统录屏器等接口。通过回调通知监听方录屏开始/结束/进程死亡。详见 [monitor-and-controller](entities/monitor-and-controller.md)

## Controller 服务（ScreenCaptureControllerServer）
独立 IPC 服务，处理 Picker 用户选择结果上报、可配置参数查询。与主 ScreenCaptureServer 分离，通过 sessionId 关联对应录屏会话。详见 [monitor-and-controller](entities/monitor-and-controller.md)

## 统计事件（StatisticalEventInfo）
录屏统计打点信息结构体，含错误码/错误信息/录制时长/用户授权/麦克风/分辨率/停止原因/启动延迟等字段。录屏结束/出错时通过 HiSysEvent 上报，用于质量监控与故障分析。详见 [error-handling-and-dfx](technologies/error-handling-and-dfx.md)

## 通知栏实时视图（NotificationLocalLiveViewContent）
录屏通知栏内容对象，支持"正在录屏"胶囊提示、暂停/停止按钮、录制时长。录屏开始时发布通知、状态变更时更新、结束时移除。详见 [error-handling-and-dfx](technologies/error-handling-and-dfx.md)

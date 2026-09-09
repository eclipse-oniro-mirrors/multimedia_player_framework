# 术语表

> 只说明模型不知道的术语，常识类不要写

## 虚拟屏幕（VirtualScreen）
ScreenCaptureServer 通过 `Rosen::ScreenManager::CreateVirtualScreen()` 创建的虚拟屏幕，将物理屏幕画面镜像到虚拟屏幕的 Surface 上。应用通过该 Surface 的 SurfaceBuffer 获取每帧视频数据。虚拟屏幕 ID 决定隐私窗口保护、镜像来源等行为。详见 [[capture-implementation-layer]]

**触发加载**：当任务涉及"虚拟屏幕/CreateVirtualScreen/DestroyVirtualScreen/SurfaceBuffer/镜像录制"时 → 必读 [[capture-implementation-layer]] + [[video-capture-and-surface]]

## 能力位图（Capability bitmask）
ScreenCaptureServer 用 7 状态枚举 + 状态-能力映射数组 `STATE_CAPS_[]` 替代 AVPlayer 的状态类继承体系。每个状态对应一组 Capability 位（CAP_INIT/CAP_CONFIG/CAP_ALIVE/CAP_POPUP/CAP_RUNNING/CAP_PAUSED/CAP_ACTIVE），`IsState(cap)` 通过位与判断当前状态是否允许某操作，非法操作返回 MSERR_INVALID_OPERATION。详见 [[state-machine]]

**触发加载**：当任务涉及"状态机/状态校验/IsState/能力位图/STATE_CAPS/非法操作"时 → 必读 [[state-machine]] + [[service-layer]]

## 隐私窗口保护（PrivacyProtected）
虚拟屏幕可设置跳过系统级/应用级隐私窗口保护。`PrivacyProtected(screenId, systemPrivacy, appPrivacy)` 设置后，含有隐私属性的窗口在录屏时被跳过（黑屏/遮盖），防止敏感信息泄露。隐私窗口出现/消失时通过 `OnStateChange(ENTER_PRIVATE_SCENE/EXIT_PRIVATE_SCENE)` 通知应用。详见 [[privacy-protection]]

**触发加载**：当任务涉及"隐私保护/PrivacyProtected/隐私窗口/ENTER_PRIVATE_SCENE/系统隐私/应用隐私"时 → 必读 [[privacy-protection]]

## 免授权权限（EXEMPT_CAPTURE_SCREEN_AUTHORIZE）
`ohos.permission.EXEMPT_CAPTURE_SCREEN_AUTHORIZE` 权限，持有该权限的系统应用可跳过隐私授权弹窗直接开始录屏。无此权限的应用需经过 POPUP_WINDOW 状态弹出隐私通知窗口等待用户授权。详见 [[privacy-protection]]

**触发加载**：当任务涉及"免授权/EXEMPT_CAPTURE_SCREEN_AUTHORIZE/隐私弹窗/POPUP_WINDOW/系统录屏"时 → 必读 [[privacy-protection]]

## 数据模式（DataType）
录屏数据输出模式：`ORIGINAL_STREAM`（原始流，应用通过 AcquireAudioBuffer/AcquireVideoBuffer 获取每帧数据）、`ENCODED_STREAM`（编码流）、`CAPTURE_FILE`（录制到文件，复用 Recorder 引擎）。不同模式决定 ScreenCaptureServer 初始化视频/音频/录制器的路径。详见 [[capture-lifecycle]]

**触发加载**：当任务涉及"数据模式/ORIGINAL_STREAM/CAPTURE_FILE/ENCODED_STREAM/AcquireBuffer"时 → 必读 [[capture-lifecycle]] + [[capture-implementation-layer]]

## 采集模式（CaptureMode）
录屏目标选择模式：`CAPTURE_HOME_SCREEN`(0)、`CAPTURE_SPECIFIED_SCREEN`(1)、`CAPTURE_SPECIFIED_WINDOW`(2)、`CAPTURE_VIRTUAL_EXTENDED_SCREEN`(3)、`CAPTURE_SPECIFIED_APP`(4)。决定虚拟屏幕创建参数、镜像来源、窗口过滤策略。详见 [[capture-lifecycle]]

**触发加载**：当任务涉及"采集模式/CaptureMode/HomeScreen/SpecifiedWindow/VirtualExtendedScreen/录制目标"时 → 必读 [[capture-lifecycle]]

## Picker 选择器
系统级 UI 扩展能力，让用户在录屏开始前选择录制目标（窗口/屏幕/应用）。`PresentPicker()` 弹出 Picker，用户选择后通过 `ScreenCaptureControllerServer::ReportAVScreenCaptureUserChoice()` 上报选择结果。`PickerMode` 控制可选目标类型组合。详见 [[ipc-communication]]

**触发加载**：当任务涉及"Picker/PresentPicker/PickerMode/用户选择/UserChoice/Controller"时 → 必读 [[ipc-communication]] + [[service-layer]]

## 音频混音（AudioDataSource MixAudio）
AudioDataSource 持有内录（inner）和麦克风（mic）两路 AudioCapturerWrapper，通过 `MixModeBufferWrite()` 将两路 PCM 数据按时间戳对齐混合后输出。视频首帧 pts 与音频首帧 pts 对齐实现音视频同步。Pause/Resume 时记录 pauseDuration 补偿时间戳偏移。详见 [[audio-capture-and-mixing]]

**触发加载**：当任务涉及"音频混音/MixAudio/AudioDataSource/内录/麦克风/音视频同步/pauseDuration"时 → 必读 [[audio-capture-and-mixing]]

## 缓冲消费者监听器（ScreenCapBufferConsumerListener）
注册到虚拟屏幕 Consumer Surface 的 `IBufferConsumerListener`，监听 `OnBufferAvailable()` 回调。内部维护独立 Buffer 线程循环 `AcquireBuffer()` 获取 SurfaceBuffer 并通过 `ScreenCaptureCallbackProxy::OnVideoBufferAvailable()` 回调给应用。Start/Stop/Release 控制线程生命周期。详见 [[video-capture-and-surface]]

**触发加载**：当任务涉及"SurfaceBuffer/BufferConsumer/OnBufferAvailable/缓冲线程/AcquireVideoBuffer"时 → 必读 [[video-capture-and-surface]] + [[capture-implementation-layer]]

## 会话管理器（ScreenCaptureServerManager）
管理 ScreenCaptureServer 实例生命周期，限制最大实例数 `maxAppLimit_=4` 和单 UID 最大会话数 `maxSessionPerUid_=4`。超限时拒绝创建并返回错误。负责 SA 注册、实例索引、进程死亡清理。详见 [[service-layer]]

**触发加载**：当任务涉及"实例限制/会话管理/ServerManager/maxAppLimit/实例数量/SA注册"时 → 必读 [[service-layer]]

## 监听器管理器（ScreenCaptureListenerManager）
统一注册/注销窗口生命周期、窗口信息变更、隐私窗口、屏幕连接、语言切换、账号切换、通话状态、音频渲染器状态、应用生命周期等系统监听器。通过 `ListenerFlag` 位图（LF_WIN_LIFECYCLE/LF_PRIVATE_WIN/LF_ACCOUNT 等）按需注册，避免每个 ScreenCaptureServer 实例重复注册。详见 [[service-layer]]

**触发加载**：当任务涉及"监听器注册/ListenerManager/ListenerFlag/窗口监听/账号切换/系统事件监听"时 → 必读 [[service-layer]]

## Monitor 单例（ScreenCaptureMonitorServer）
进程级单例（`GetInstance()`），追踪当前所有录屏进程状态。提供 `IsScreenCaptureWorking()` 返回录屏进程 PID 列表，`IsSystemScreenRecorder(pid)` 判断是否系统录屏器。通过 `IStandardScreenCaptureMonitorListener` 回调 OnScreenCaptureStarted/Finished/Died 通知监听方。详见 [[service-layer]]

**触发加载**：当任务涉及"Monitor/录屏监控/IsScreenCaptureWorking/系统录屏器/录屏状态通知"时 → 必读 [[service-layer]]

## Controller 服务（ScreenCaptureControllerServer）
独立 IPC 服务（3 个消息码），处理 `ReportAVScreenCaptureUserChoice()` 上报 Picker 用户选择结果、`GetAVScreenCaptureConfigurableParameters()` 查询可配置参数。与主 ScreenCaptureServer 分离，通过 sessionId 关联对应录屏会话。详见 [[ipc-communication]]

**触发加载**：当任务涉及"Controller/UserChoice/用户选择上报/ControllerServer/sessionId"时 → 必读 [[ipc-communication]]

## 统计事件（StatisticalEventInfo）
录屏统计打点信息结构体，含 errCode/errorMsg/captureDuration/userAgree/requireMic/enableMic/videoResolution/stopReason/startLatency 等字段。录屏结束/出错时通过 HiSysEvent 上报，用于质量监控与故障分析。详见 [[error-handling-and-dfx]]

**触发加载**：当任务涉及"统计打点/StatisticalEventInfo/HiSysEvent/录屏时长/启动延迟/stopReason"时 → 必读 [[error-handling-and-dfx]]

## 通知栏实时视图（NotificationLocalLiveViewContent）
录屏通知栏内容对象，包含 CAPSULE/BUTTON/TIME 等标志位，支持"正在录屏"胶囊提示、暂停/停止按钮、录制时长。ScreenCaptureServer 在录屏开始时发布通知、状态变更时更新、结束时移除。详见 [[error-handling-and-dfx]]

**触发加载**：当任务涉及"通知栏/LocalLiveView/录屏通知/胶囊/通知按钮/notificationId"时 → 必读 [[error-handling-and-dfx]]

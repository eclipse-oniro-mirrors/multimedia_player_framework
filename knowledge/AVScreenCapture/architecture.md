# 架构设计及约束

> **全局性**架构设计原则及约束说明

## 架构设计

### 设计原则

| 原则 | 描述 | 理由 |
|------|------|------|
| Client-Server 进程隔离 | 录屏客户端运行在应用进程，服务端运行在媒体服务进程，通过 IPC 通信 | 隔离录屏崩溃风险，支持多客户端共享服务端，IPC 是模块边界 |
| 无独立引擎层 | 视频采集直接调用 Rosen VirtualScreen，音频采集直接调用 AudioCapturer，文件录制复用 Recorder 引擎 | 屏幕录制本质是系统显示/音频能力的直接采集，无需 Pipeline 编排，引入引擎层反而增加不必要的间接调用 |
| 能力位图状态机 | ScreenCaptureServer 用 7 状态枚举 + 状态-能力映射数组 `STATE_CAPS_[]` 替代状态类继承，`IsState(cap)` 位与校验 | 比状态类继承更轻量，状态-能力关系集中可查，新增状态只需扩展数组 |
| 隐私保护优先 | 录屏前必须经过权限校验 + 隐私授权弹窗（或免授权权限），隐私窗口实时跳过保护 | 屏幕录制涉及用户敏感内容，隐私保护是合规底线 |
| 监听器统一管理 | ScreenCaptureListenerManager 统一注册/注销窗口/屏幕/账号/通话等系统监听器，按 ListenerFlag 位图按需注册 | 避免每个 Server 实例重复注册系统监听器，减少资源占用与回调风暴 |
| Picker 用户选择模式 | PresentPicker 弹出系统 UI 让用户选择录制目标，Controller 服务接收选择结果 | 录制指定窗口/应用时需用户明确选择目标，避免应用擅自录制其它人窗口 |
| 三子系统分离 | ScreenCapture（主录屏）、ScreenCaptureController（用户选择）、ScreenCaptureMonitor（状态监控）独立 SA | 职责单一，Monitor 单例不依赖主录屏实例即可工作 |
| 实例数量限制 | ScreenCaptureServerManager 限制 maxAppLimit_=4 / maxSessionPerUid_=4 | 防止单一应用耗尽系统录屏资源 |

### 逻辑架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        API 接入层                                 │
│  ┌─────────────────┐ ┌──────────────────┐ ┌─────────────────┐  │
│  │ AVScreenCapture │ │AVScreenCapture   │ │AVScreenCapture  │  │
│  │ (ArkTS/JS/C API)│ │Monitor(ArkTS/JS) │ │Controller(C API)│  │
│  └───────┬─────────┘ └───────┬──────────┘ └───────┬─────────┘  │
├──────────┼───────────────────┼────────────────────┼────────────┤
│          │     NAPI / CJ-FFI / ANI Bridge Layer   │            │
├──────────┼───────────────────┼────────────────────┼────────────┤
│                        IPC 通信层                                 │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ScreenCaptureClient ←IPC→ ScreenCaptureServiceStub/Proxy   │  │
│  │ScreenCaptureControllerClient ←IPC→ ControllerStub/Proxy    │  │
│  │ScreenCaptureMonitorClient ←IPC→ MonitorStub/Proxy          │  │
│  │ScreenCaptureListener ←IPC→ ScreenCaptureCallbackProxy      │  │
│  └────────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────┤
│                        服务层                                     │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ ScreenCaptureServer (7状态能力位图 + 权限/隐私/采集编排)    │  │
│  │ ScreenCaptureServerManager (实例限制 maxApp=4/uid=4)        │  │
│  │ ScreenCaptureListenerManager (系统监听器统一注册)           │  │
│  │ ScreenCaptureControllerServer (用户选择处理)                 │  │
│  │ ScreenCaptureMonitorServer (录屏状态单例追踪)               │  │
│  └────────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────┤
│                    采集实现层                                     │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────────────┐    │
│  │视频采集      │  │音频采集         │  │文件录制            │    │
│  │Rosen         │  │AudioCapturer    │  │RecorderServer     │    │
│  │VirtualScreen │  │Wrapper          │  │(复用player_framework│   │
│  │+Surface      │  │+AudioDataSource │  │ Recorder引擎)      │    │
│  │+BufferConsumer│ │  (混音)        │  │                   │    │
│  │Listener      │  │                │  │                   │    │
│  └──────┬───────┘  └───────┬────────┘  └────────┬──────────┘    │
│         │                  │                    │               │
│  PrivacyProtected   MixModeBufferWrite    SetAudioDataSource    │
│  ExcludeContent     Pause/Resume补偿      InitRecorderInfo      │
├──────────────────────────────────────────────────────────────────┤
│                    InnerAPI 契约层                                 │
│  ┌──────────────────┐ ┌───────────────────┐ ┌────────────────┐  │
│  │IScreenCapture    │ │IScreenCapture     │ │IRecorderService│  │
│  │Service (41码)     │ │Controller (3码)   │ │(复用Recorder)  │  │
│  ├──────────────────┤ ├───────────────────┤ ├────────────────┤  │
│  │IScreenCapture    │ │IScreenCaptureMon  │ │ScreenCapture   │  │
│  │MonitorService    │ │MonitorListener    │ │(抽象接口)      │  │
│  │(6码)              │ │(3回调)            │ │ScreenCaptureCb│  │
│  └──────────────────┘ └───────────────────┘ └────────────────┘  │
├──────────────────────────────────────────────────────────────────┤
│                    原子能力层                                     │
│  ┌─────────────────┐ ┌─────────────────┐ ┌──────────────────┐  │
│  │Rosen             │ │AudioStandard     │ │Notification      │  │
│  │ScreenManager     │ │AudioCapturer     │ │NotificationMgr   │  │
│  │WindowManager     │ │AudioPolicyMgr    │ │PrivacyKit        │  │
│  │DisplayManager    │ │                  │ │AccountManager    │  │
│  └────────┬─────────┘ └────────┬─────────┘ └────────┬─────────┘  │
│           ↓                    ↓                    ↓            │
│      HDI 显示合成          HDI 音频采集          HDI 编解码       │
└──────────────────────────────────────────────────────────────────┘
```

### 模块职责

| 模块 | 类型 | 模块职责 | 关键文件 |
|------|------|---------|---------|
| AVScreenCapture (C API) | ohos_shared_library | C API 录屏器，OH_AVScreenCapture_* 接口族 | `frameworks/native/capi/screencapture/native_avscreen_capture.cpp` |
| AVScreenCapture (ArkTS/JS) | ohos_shared_library | NAPI 桥接层，AVScreenCapture JS 类 | `frameworks/js/screencapture/` |
| ScreenCaptureImpl | ohos_shared_library | Native 实现，持有 IScreenCaptureService 代理，转发调用到服务端 | `frameworks/native/screen_capture/screen_capture_impl.cpp` |
| ScreenCaptureMonitorImpl | ohos_shared_library | Monitor 客户端实现，持有 MonitorService 代理 | `frameworks/native/screen_capture/screen_capture_monitor_impl.cpp` |
| ScreenCaptureControllerImpl | ohos_shared_library | Controller 客户端实现，上报用户选择 | `frameworks/native/screen_capture/screen_capture_controller_impl.cpp` |
| ScreenCaptureClient | ohos_shared_library | 应用进程录屏代理，持有 IPC Proxy + ListenerStub | `services/services/screen_capture/client/screen_capture_client.cpp` |
| ScreenCaptureServiceStub | ohos_shared_library | IPC 服务端入口，41 消息码分发，权限校验 | `services/services/screen_capture/ipc/screen_capture_service_stub.cpp` |
| ScreenCaptureServer | ohos_shared_library | 服务端核心，7 状态能力位图 + 权限/隐私 + 采集编排 | `services/services/screen_capture/server/screen_capture_server.cpp` |
| ScreenCaptureServerManager | ohos_shared_library | 实例管理，限制 maxAppLimit_=4 / maxSessionPerUid_=4 | `services/services/screen_capture/server/screen_capture_server_manager.cpp` |
| ScreenCaptureListenerManager | ohos_shared_library | 系统监听器统一注册/注销，ListenerFlag 位图按需注册 | `services/services/screen_capture/server/screen_capture_listener_manager.cpp` |
| ScreenCapBufferConsumerListener | ohos_shared_library | 视频帧缓冲监听，独立线程获取 SurfaceBuffer 回调应用 | `services/services/screen_capture/server/screen_cap_buffer_consumer_listener.cpp` |
| AudioCapturerWrapper | ohos_shared_library | 音频采集封装，封装 AudioStandard::AudioCapturer + 回调 | `services/services/screen_capture/server/audio_capturer_wrapper.cpp` |
| AudioDataSource | ohos_shared_library | 音频混音 + 时间戳同步 + Pause/Resume 补偿 | `services/services/screen_capture/server/audio_data_source.cpp` |
| ScreenCaptureCallbackProxy | ohos_shared_library | 服务端回调代理，向应用端发送 8 种回调 | `services/services/screen_capture/server/screen_capture_callback_proxy.cpp` |
| ScreenCaptureControllerServer | ohos_shared_library | 用户选择处理服务，3 消息码 | `services/services/screen_capture/server/screen_capture_controller_server.cpp` |
| ScreenCaptureMonitorServer | ohos_shared_library | 录屏状态监控单例，追踪录屏进程 | `services/services/screen_capture_monitor/server/screen_capture_monitor_server.cpp` |
| ScreenCaptureServiceProviders | ohos_shared_library | 依赖注入工厂，CreateRecorder/GetMonitor/GetAccountObserver | `services/services/screen_capture/server/screen_capture_service_providers.cpp` |
| media_service_screen_capture | ohos_shared_library | 构建产物，导出 CreateScreenCaptureServer 等 4 个符号 | `services/services/screen_capture/BUILD.gn` |

### 技术选型

| 类别 | 技术选型 | 说明 |
|------|---------|------|
| 进程间通信 | OHOS IPC（MessageParcel / IRemoteStub） | Client-Server 双进程，41+3+6 消息码 + 8+3 回调码 |
| 视频采集 | Rosen::ScreenManager::CreateVirtualScreen | 创建虚拟屏幕镜像物理屏幕，Consumer Surface 获取 SurfaceBuffer |
| 视频帧传递 | Surface + IBufferConsumerListener | Producer（虚拟屏幕）写入 → Consumer（ScreenCapBufferConsumerListener）读取 |
| 音频采集 | AudioStandard::AudioCapturer | AudioCapturerWrapper 封装，支持 MIC/ALL_PLAYBACK/APP_PLAYBACK |
| 音频混音 | AudioDataSource::MixModeBufferWrite | 内录 + 麦克风两路 PCM 按时间戳对齐混合 |
| 文件录制 | RecorderServer::Create()（IRecorderService） | 复用 player_framework Recorder 引擎，SetAudioDataSource 注入混音源 |
| 隐私保护 | PrivacyKit + Rosen PrivacyProtected | 权限申请/释放、隐私窗口跳过保护、白名单/内容过滤 |
| 状态校验 | Capability bitmask + STATE_CAPS_[] | 7 状态 × 8 能力位，IsState() 位与判断 |
| 监听器管理 | ListenerFlag 位图 + 按需注册 | LF_ALL = 10 种监听器位或组合 |
| 通知栏 | NotificationLocalLiveViewContent | 录屏胶囊 + 按钮 + 时长实时更新 |
| 权限管理 | PrivacyKit::StartUsingPermission/StopUsingPermission | CAPTURE_SCREEN 权限运行时申请/释放 + 使用记录 |

### 基础设施

> 全局架构基础设施，约束模型编码，包括日志与打点、进程监控、实例限制、通知栏等统一的代码基础设施

| 基础设施 | 功能说明 | 关键接口描述 |
|----------|---------|------------|
| 实例限制 | ScreenCaptureServerManager 限制全局实例数和单 UID 会话数 | `SetAndCheckLimit()`、`SetAndCheckSaLimit()`，超限返回错误 |
| 录屏监控 | MonitorServer 单例追踪录屏进程，回调 Started/Finished/Died | `IsScreenCaptureWorking()`、`IsSystemScreenRecorder()` |
| 系统监听器 | ListenerManager 统一注册窗口/屏幕/账号/通话/音频等系统事件 | `RegisterListeners(flags)`、`UnregisterListeners(flags)` |
| 通知栏 | 录屏进行中发布实时通知，支持暂停/停止按钮 | `NotificationLocalLiveViewContent` + `NotificationContent` |
| 统计打点 | 录屏结束/出错时上报 StatisticalEventInfo | HiSysEvent 上报时长/分辨率/麦克风/错误等 |
| 进程死亡 | DeathRecipient 监控服务端死亡，客户端自动清理 | `ScreenCaptureClient::MediaServerDied()` |
| 权限生命周期 | PrivacyKit 运行时权限申请/释放/记录 | `StartUsingPermission` / `StopUsingPermission` / `AddPermissionUsedRecord` |

### 非功能设计

> 此章节仅描述**全局性**的非功能实现方案及原则

#### 可测试性设计

| 可测试性场景 | 方案设计 |
|-------------|---------|
| 依赖注入测试 | ScreenCaptureServiceProviders 支持注入 Mock Recorder/Monitor/AccountObserver，验证采集编排逻辑 |
| IPC 接口级测试 | ScreenCaptureClient/ServiceStub 通过 IPC Proxy/Stub 可独立 Mock 对端进行测试 |
| 状态机测试 | 能力位图状态机可通过构造不同 captureState_ 验证 IsState() 返回值，无需状态类 Mock |

#### 可靠性设计

| 可靠性场景 | 方案设计 |
|-----------|---------|
| 服务端崩溃隔离 | Client-Server 双进程，媒体服务崩溃不影响应用进程 |
| IPC 异常恢复 | DeathRecipient 监控对端死亡，MediaServerDied 清理 Proxy |
| 虚拟屏幕资源释放 | Stop/Release 时 DestroyVirtualScreen + StopBufferThread + Release，确保 Rosen 资源不泄漏 |
| 音频采集器释放 | AudioCapturerWrapper 析构时 Stop/Release AudioCapturer，防止音频设备占用 |
| 隐私窗口实时保护 | OnPrivateWindowChange 实时触发 ENTER_PRIVATE_SCENE/EXIT_PRIVATE_SCENE 回调 |

#### 性能设计

| 性能场景 | 方案设计 |
|----------|---------|
| 视频帧零拷贝 | SurfaceBuffer 通过 sptr 引用传递，AcquireVideoBuffer 返回直接指针无需拷贝 |
| 音频混音预分配 | CacheBuffer 预分配音频缓冲，避免每帧 new/malloc |
| 监听器按需注册 | ListenerFlag 位图仅注册当前模式需要的系统监听器，减少无效回调 |
| 实例数量限制 | maxAppLimit_=4 防止资源耗尽 |

#### 内存设计

| 内存场景 | 方案设计 |
|----------|---------|
| SurfaceBuffer 及时释放 | AcquireVideoBuffer 后应用 ReleaseVideoBuffer 归还，防止 Consumer 队列积压 |
| AudioBuffer 及时释放 | AcquireAudioBuffer 后 ReleaseAudioBuffer 归还，按 AudioCaptureSourceType 区分 |
| 智能指针管理 | recorder_/audioSource_/providers_ 等使用 shared_ptr，RAII 自动释放 |
| 虚拟屏幕按需创建 | 仅 Start 时 CreateVirtualScreen，Stop/Release 时 Destroy |

#### 安全与隐私设计

| 安全与隐私场景 | 设计方案 |
|--------------|---------|
| 进程隔离 | Client-Server 双进程，录屏崩溃不影响应用进程 |
| 权限校验 | StartScreenCapture 前校验 CAPTURE_SCREEN 权限 + 隐私授权 |
| 免授权通道 | EXEMPT_CAPTURE_SCREEN_AUTHORIZE 权限跳过弹窗，仅系统应用持有 |
| 隐私窗口保护 | PrivacyProtected 设置虚拟屏幕跳过系统/应用隐私窗口 |
| 白名单窗口 | AddWhiteListWindows/RemoveWhiteListWindows 控制特定窗口不受隐私保护 |
| 内容过滤 | ExcludeContent 过滤指定音频内容 + 窗口 ID |
| 状态机约束 | 能力位图校验，非法操作返回 MSERR_INVALID_OPERATION |
| 通话中断 | 通话状态变化时停止录屏（可配置 keepCaptureDuringCall 策略） |

## 架构约束

> **全局性**的架构约束说明，需要包含what/why/how

- **IPC 是模块边界**
  - **what**：所有跨进程调用必须通过 IPC Proxy/Stub，严禁共享裸指针或引用
  - **why**：进程隔离是崩溃安全的基础，共享指针会绕过进程保护导致级联故障
  - **how**：所有跨进程数据通过 MessageParcel 序列化，客户端持有 ScreenCaptureServiceProxy，服务端实现 ScreenCaptureServiceStub

- **无独立引擎层（直接调用系统能力）**
  - **what**：视频采集直接调用 Rosen VirtualScreen，音频采集直接调用 AudioCapturer，文件录制复用 Recorder 引擎，严禁为录屏单独引入引擎选择/Pipeline 层
  - **why**：屏幕录制本质是系统能力的直接采集，引入引擎层会增加不必要的间接调用和抽象成本
  - **how**：ScreenCaptureServer 通过 ScreenCaptureServiceProviders 获取 RecorderServer::Create()，直接调用 Rosen::ScreenManager 和 AudioStandard::AudioCapturer

- **能力位图状态机保护**
  - **what**：所有操作必须经过 `IsState(cap)` 能力位校验，非法操作返回 MSERR_INVALID_OPERATION，严禁绕过状态机直接执行
  - **why**：未校验的操作可能导致未定义行为，如未配置就 Start、录屏中重复 Start
  - **how**：每个操作入口先 `CHECK_AND_RETURN_RET_LOG(IsState(CAP_xxx), ...)`，能力位由 `STATE_CAPS_[captureState_] & cap` 计算

- **隐私保护优先**
  - **what**：录屏开始前必须完成权限校验 + 隐私授权（弹窗或免授权权限），录屏中隐私窗口必须实时跳过保护，严禁跳过隐私流程
  - **why**：屏幕录制涉及用户敏感内容，隐私保护是合规底线，遗漏会导致敏感信息泄露
  - **how**：StartScreenCapture 前校验 CAPTURE_SCREEN 权限，无 EXEMPT 权限走 POPUP_WINDOW 弹窗流程，PrivacyProtected 设置虚拟屏幕隐私跳过，OnPrivateWindowChange 实时回调

- **实例数量限制**
  - **what**：全局录屏实例不超过 maxAppLimit_=4，单 UID 不超过 maxSessionPerUid_=4，严禁超限创建
  - **why**：虚拟屏幕和 AudioCapturer 是系统稀缺资源，无限创建会耗尽资源
  - **how**：SetAndCheckLimit/SetAndCheckSaLimit 在创建前检查计数，超限返回错误码

- **监听器统一注册管理**
  - **what**：窗口/屏幕/账号/通话等系统监听器必须通过 ScreenCaptureListenerManager 统一注册/注销，严禁各实例独立注册
  - **why**：独立注册会导致重复回调、资源浪费、注销遗漏
  - **how**：通过 ListenerFlag 位图按需 RegisterListeners(flags)，释放时 UnregisterListeners(LF_ALL) 统一注销

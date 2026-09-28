# 架构设计及约束

> **全局性**架构设计原则及约束说明

## 架构设计

### 设计原则

| 原则 | 描述 | 理由 |
|------|------|------|
| Client-Server 进程隔离 | 录屏客户端运行在应用进程，服务端运行在媒体服务进程，通过 IPC 通信 | 隔离录屏崩溃风险，支持多客户端共享服务端，IPC 是模块边界 |
| 无独立引擎层 | 视频采集直接调用 Rosen VirtualScreen，音频采集直接调用 AudioCapturer，文件录制复用 Recorder 引擎 | 屏幕录制本质是系统显示/音频能力的直接采集，无需 Pipeline 编排，引入引擎层反而增加不必要的间接调用 |
| 能力位图状态机 | 用 7 状态枚举 + 状态-能力映射数组替代状态类继承，`IsState(cap)` 位与校验 | 比状态类继承更轻量，状态-能力关系集中可查，新增状态只需扩展数组 |
| 隐私保护优先 | 录屏前必须经过权限校验 + 隐私授权弹窗（或免授权权限），隐私窗口实时跳过保护 | 屏幕录制涉及用户敏感内容，隐私保护是合规底线 |
| 监听器统一管理 | 统一注册/注销窗口/屏幕/账号/通话等系统监听器，按 ListenerFlag 位图按需注册 | 避免每个 Server 实例重复注册系统监听器，减少资源占用与回调风暴 |
| Picker 用户选择模式 | 弹出系统 UI 让用户选择录制目标，Controller 服务接收选择结果 | 录制指定窗口/应用时需用户明确选择目标，避免应用擅自录制其它人窗口 |
| 三子系统分离 | ScreenCapture（主录屏）、ScreenCaptureController（用户选择）、ScreenCaptureMonitor（状态监控）独立 SA | 职责单一，Monitor 单例不依赖主录屏实例即可工作 |
| 实例数量限制 | 限制全局最大实例数和单 UID 最大会话数 | 防止单一应用耗尽系统录屏资源 |

### 逻辑架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        API 接入层                                 │
│  AVScreenCapture (ArkTS/JS/C) · AVScreenCaptureMonitor           │
│  · AVScreenCaptureController                                     │
├──────────────────────────────────────────────────────────────────┤
│                   NAPI / CJ-FFI / ANI Bridge Layer              │
├──────────────────────────────────────────────────────────────────┤
│                        IPC 通信层                                 │
│  ScreenCapture · Controller · Monitor 各自 Client ↔ Stub/Proxy   │
│  ScreenCaptureListener 双向回调通路                              │
├──────────────────────────────────────────────────────────────────┤
│                           服务层                                  │
│  ScreenCaptureServer (7状态能力位图 + 权限/隐私/采集编排)          │
│  ScreenCaptureServerManager (实例限制)                            │
│  ScreenCaptureListenerManager (系统监听器统一注册)                 │
│  ScreenCaptureControllerServer (用户选择处理)                     │
│  ScreenCaptureMonitorServer (录屏状态单例追踪)                    │
├──────────────────────────────────────────────────────────────────┤
│                       采集实现层                                  │
│  视频采集: Rosen VirtualScreen + Surface + BufferConsumerListener │
│  音频采集: AudioCapturerWrapper + AudioDataSource (混音/同步)      │
│  文件录制: RecorderServer (复用 player_framework Recorder 引擎)   │
│  隐私保护: PrivacyProtected / ExcludeContent                     │
├──────────────────────────────────────────────────────────────────┤
│                      InnerAPI 契约层                              │
│  IScreenCaptureService · IScreenCaptureController                │
│  IScreenCaptureMonitorService · ScreenCapture / ScreenCaptureCb │
│  IRecorderService (复用 Recorder)                                │
├──────────────────────────────────────────────────────────────────┤
│                       原子能力层                                  │
│  Rosen ScreenManager/WindowManager/DisplayManager               │
│  AudioStandard AudioCapturer/AudioPolicyMgr                      │
│  Notification · PrivacyKit · AccountManager                      │
│      ↓ HDI 显示合成        ↓ HDI 音频采集        ↓ HDI 编解码     │
└──────────────────────────────────────────────────────────────────┘
```

### 模块职责

| 模块 | 类型 | 模块职责 |
|------|------|---------|
| AVScreenCapture (ArkTS/JS) | ohos_shared_library | NAPI 桥接层，AVScreenCapture JS 类 |
| AVScreenCapture (C API) | ohos_shared_library | C API 录屏器，OH_AVScreenCapture_* 接口族 |
| ScreenCaptureImpl | ohos_shared_library | Native 实现，持有服务代理，转发调用到服务端 |
| ScreenCaptureMonitorImpl / ControllerImpl | ohos_shared_library | Monitor/Controller 客户端实现 |
| ScreenCaptureClient | ohos_shared_library | 应用进程录屏代理，持有 IPC Proxy + Listener Stub |
| ScreenCaptureServiceStub | ohos_shared_library | IPC 服务端入口，消息码分发 + 权限校验 |
| ScreenCaptureServer | ohos_shared_library | 服务端核心，7 状态能力位图 + 权限/隐私 + 采集编排 |
| ScreenCaptureServerManager | ohos_shared_library | 实例管理，全局/单 UID 实例数限制 |
| ScreenCaptureListenerManager | ohos_shared_library | 系统监听器统一注册/注销，ListenerFlag 位图按需注册 |
| ScreenCapBufferConsumerListener | ohos_shared_library | 视频帧缓冲监听，独立线程获取 SurfaceBuffer 回调应用 |
| AudioCapturerWrapper / AudioDataSource | ohos_shared_library | 音频采集封装 / 混音 + 时间戳同步 + Pause/Resume 补偿 |
| ScreenCaptureCallbackProxy | ohos_shared_library | 服务端回调代理，向应用端发送 8 种回调 |
| ScreenCaptureControllerServer | ohos_shared_library | 用户选择处理服务 |
| ScreenCaptureMonitorServer | ohos_shared_library | 录屏状态监控单例，追踪录屏进程 |
| ScreenCaptureServiceProviders | ohos_shared_library | 依赖注入工厂（Recorder/Monitor/AccountObserver） |

### 技术选型

| 类别 | 技术选型 | 说明 |
|------|---------|------|
| 进程间通信 | OHOS IPC（MessageParcel / IRemoteStub） | Client-Server 双进程，4 组 IPC 接口 + 双向回调 |
| 视频采集 | Rosen VirtualScreen + Surface | 创建虚拟屏幕镜像物理屏幕，Consumer Surface 获取 SurfaceBuffer |
| 视频帧传递 | Surface + IBufferConsumerListener | Producer 写入 → Consumer 读取 |
| 音频采集 | AudioStandard::AudioCapturer | 支持 MIC/ALL_PLAYBACK/APP_PLAYBACK |
| 音频混音 | AudioDataSource | 内录 + 麦克风两路 PCM 按时间戳对齐混合 |
| 文件录制 | RecorderServer（IRecorderService） | 复用 player_framework Recorder 引擎 |
| 隐私保护 | PrivacyKit + Rosen PrivacyProtected | 权限申请/释放、隐私窗口跳过保护、白名单/内容过滤 |
| 状态校验 | Capability bitmask + 状态-能力映射 | 7 状态 × 能力位，位与判断 |
| 监听器管理 | ListenerFlag 位图 + 按需注册 | 多种监听器位或组合 |
| 通知栏 | NotificationLocalLiveViewContent | 录屏胶囊 + 按钮 + 时长实时更新 |
| 权限管理 | PrivacyKit | CAPTURE_SCREEN 权限运行时申请/释放 + 使用记录 |

### 基础设施

> 全局架构基础设施，约束模型编码

| 基础设施 | 功能说明 |
|----------|---------|
| 实例限制 | 限制全局实例数和单 UID 会话数，超限返回错误 |
| 录屏监控 | MonitorServer 单例追踪录屏进程，回调 Started/Finished/Died |
| 系统监听器 | 统一注册窗口/屏幕/账号/通话/音频等系统事件 |
| 通知栏 | 录屏进行中发布实时通知，支持暂停/停止按钮 |
| 统计打点 | 录屏结束/出错时上报 StatisticalEventInfo |
| 进程死亡 | DeathRecipient 监控服务端死亡，客户端自动清理 |
| 权限生命周期 | PrivacyKit 运行时权限申请/释放/记录 |

### 非功能设计

> 此章节仅描述**全局性**的非功能实现方案及原则

#### 可测试性设计

| 可测试性场景 | 方案设计 |
|-------------|---------|
| 依赖注入测试 | 依赖注入接口支持注入 Mock Recorder/Monitor/AccountObserver，验证采集编排逻辑 |
| IPC 接口级测试 | Client/ServiceStub 通过 IPC Proxy/Stub 可独立 Mock 对端进行测试 |
| 状态机测试 | 能力位图状态机可通过构造不同状态验证 IsState() 返回值，无需状态类 Mock |

#### 可靠性设计

| 可靠性场景 | 方案设计 |
|-----------|---------|
| 服务端崩溃隔离 | Client-Server 双进程，媒体服务崩溃不影响应用进程 |
| IPC 异常恢复 | DeathRecipient 监控对端死亡，清理 Proxy |
| 虚拟屏幕资源释放 | Stop/Release 时销毁虚拟屏幕 + 停止缓冲线程 + 释放，确保 Rosen 资源不泄漏 |
| 音频采集器释放 | 封装类析构时 Stop/Release AudioCapturer，防止音频设备占用 |
| 隐私窗口实时保护 | 隐私窗口变更实时触发 ENTER_PRIVATE_SCENE/EXIT_PRIVATE_SCENE 回调 |

#### 性能设计

| 性能场景 | 方案设计 |
|----------|---------|
| 视频帧零拷贝 | SurfaceBuffer 通过引用传递，AcquireVideoBuffer 返回直接指针无需拷贝 |
| 音频混音预分配 | 预分配音频缓冲，避免每帧 new/malloc |
| 监听器按需注册 | 位图仅注册当前模式需要的系统监听器，减少无效回调 |
| 实例数量限制 | 防止资源耗尽 |

#### 内存设计

| 内存场景 | 方案设计 |
|----------|---------|
| SurfaceBuffer 及时释放 | Acquire 后应用 Release 归还，防止 Consumer 队列积压 |
| AudioBuffer 及时释放 | Acquire 后 Release 归还，按 AudioCaptureSourceType 区分 |
| 智能指针管理 | recorder_/audioSource_ 等使用 shared_ptr，RAII 自动释放 |
| 虚拟屏幕按需创建 | 仅 Start 时创建，Stop/Release 时销毁 |

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

> **全局性**的架构约束说明，需要包含 what/why/how

- **IPC 是模块边界**
  - **what**：所有跨进程调用必须通过 IPC Proxy/Stub，严禁共享裸指针或引用
  - **why**：进程隔离是崩溃安全的基础，共享指针会绕过进程保护导致级联故障
  - **how**：所有跨进程数据通过 MessageParcel 序列化，客户端持有 Proxy，服务端实现 Stub

- **无独立引擎层（直接调用系统能力）**
  - **what**：视频采集直接调用 Rosen VirtualScreen，音频采集直接调用 AudioCapturer，文件录制复用 Recorder 引擎，严禁为录屏单独引入引擎选择/Pipeline 层
  - **why**：屏幕录制本质是系统能力的直接采集，引入引擎层会增加不必要的间接调用和抽象成本
  - **how**：通过依赖注入接口获取 RecorderServer 实例，直接调用 Rosen 和 AudioStandard

- **能力位图状态机保护**
  - **what**：所有操作必须经过能力位校验，非法操作返回 MSERR_INVALID_OPERATION，严禁绕过状态机直接执行
  - **why**：未校验的操作可能导致未定义行为，如未配置就 Start、录屏中重复 Start
  - **how**：每个操作入口先校验当前状态能力位，能力位由状态-能力映射数组按位与计算

- **隐私保护优先**
  - **what**：录屏开始前必须完成权限校验 + 隐私授权（弹窗或免授权权限），录屏中隐私窗口必须实时跳过保护，严禁跳过隐私流程
  - **why**：屏幕录制涉及用户敏感内容，隐私保护是合规底线，遗漏会导致敏感信息泄露
  - **how**：Start 前校验 CAPTURE_SCREEN 权限，无 EXEMPT 权限走弹窗流程，PrivacyProtected 设置虚拟屏幕隐私跳过，隐私窗口变更实时回调

- **实例数量限制**
  - **what**：全局录屏实例和单 UID 会话数不超过上限，严禁超限创建
  - **why**：虚拟屏幕和 AudioCapturer 是系统稀缺资源，无限创建会耗尽资源
  - **how**：创建前检查全局/单 UID 计数，超限返回错误码

- **监听器统一注册管理**
  - **what**：窗口/屏幕/账号/通话等系统监听器必须通过统一管理器注册/注销，严禁各实例独立注册
  - **why**：独立注册会导致重复回调、资源浪费、注销遗漏
  - **how**：通过 ListenerFlag 位图按需注册，释放时统一注销全部

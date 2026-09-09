# 服务层实体

> ScreenCaptureServer、ScreenCaptureServerManager、监听器管理等服务端核心类

## 实体概念

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| ScreenCaptureServer | 屏幕录制服务端核心类，实现 IScreenCaptureService + IScreenCaptureEventListener | 7 状态能力位图状态机；TaskQueue 异步队列；AVScreenCaptureConfig 统一配置；虚拟屏幕管理（MakeVirtualScreenMirror/MakeVirtualScreenExtended）；音频采集（AudioCapturerWrapper）+ 文件录制（IRecorderService）；隐私授权弹窗；互斥锁保护状态/配置 | 核心服务类 |
| ScreenCaptureServerManager | 单例管理器，管理屏幕录制实例映射表 | GetNewSessionId 分配会话 ID；CanScreenCaptureInstanceBeCreate 实例数限制；CheckSCServerSpecifiedDataTypeNum 数据类型限制；SA 应用映射管理 | 全局单例 |
| ScreenCaptureServerBase | 基类，定义状态枚举/能力位图/统计事件信息 | AVScreenCaptureState 7 状态；Capability 能力位图；AVScreenCaptureAvType/AVScreenCaptureDataMode/StopReason 枚举；StatisticalEventInfo DFX 统计 | 基类 |
| ScreenCaptureCallbackProxy | 服务端回调代理，shared_mutex 保护 | SetCallback 设置回调；SetBufferActive 控制缓冲回调；OnError/OnAudioBufferAvailable/OnVideoBufferAvailable/OnStateChange/OnDisplaySelected/OnCaptureContentChanged/OnUserSelected/OnPrivacyProtect 8 个回调转发 | 回调代理 |
| ScreenCaptureListenerManager | 监听器统一管理，ListenerFlag 位图控制注册 | RegisterListeners/UnregisterListeners 按位图注册注销；管理 9 类 Wrapper；ExecuteIf 模板按标志执行 | 监听器管理 |
| IScreenCaptureEventListener | 事件监听纯虚接口，12 个回调 | OnWindowLifecycle/OnWindowInfoChanged/OnPrivateWindowChange/OnScreenConnect/OnScreenDisconnect/OnLanguageSwitch/OnRecordDisplayChange/OnCallStateChanged/OnAccountSwitched/OnAudioRendererStateChanged/OnBatchLifecycleEvent/OnAppInstanceLifecycleEvent | 纯虚接口 |
| SessionLifecycleListenerWrapper | 窗口生命周期监听 Wrapper | OnLifecycleEvent/OnBatchLifecycleEvent/OnAppInstanceLifecycleEvent 转发 | 监听器 Wrapper |
| WindowInfoListenerWrapper | 窗口信息变更监听 Wrapper | OnWindowInfoChanged 转发；SetWindowId 设置关注窗口 | 监听器 Wrapper |
| RecordDisplayListenerWrapper | 录制屏幕变更监听 Wrapper | OnChange(displayIds) 转发 | 监听器 Wrapper |
| PrivateWindowListenerWrapper | 隐私窗口监听 Wrapper | OnPrivateWindow(hasPrivate) 转发 | 监听器 Wrapper |
| ScreenConnectListenerWrapper | 屏幕连接监听 Wrapper | OnConnect/OnDisconnect/OnChange 转发 | 监听器 Wrapper |
| LanguageSwitchSubscriberWrapper | 语言切换监听 Wrapper | OnReceiveEvent 转发 | 监听器 Wrapper |
| AccountObserverCallbackWrapper | 账号切换监听 Wrapper | OnAccountsSwitch 转发 | 监听器 Wrapper |
| InCallObserverCallbackWrapper | 通话状态监听 Wrapper | OnTelCallStateUpdated 转发（SUPPORT_CALL） | 监听器 Wrapper |
| AudioRendererCallbackWrapper | 音频渲染器状态监听 Wrapper | OnRendererStateChange 转发 | 监听器 Wrapper |
| IScreenCaptureServiceProviders | 依赖注入接口 | GetScreenCaptureMonitor 获取 Monitor；CreateRecorder 创建录制器；GetAccountObserver 获取账号观察者 | 依赖注入接口 |
| ScreenCaptureControllerServer | 用户选择处理服务端 | ReportAVScreenCaptureUserChoice JSON 解析分发；GetAVScreenCaptureConfigurableParameters 获取配置参数 | 服务端类 |
| ScreenCaptureMonitorServer | Monitor 单例，IInnerScreenCaptureMonitorService | runningCapturePidCounts_ 运行中 PID 计数；screenCaptureMonitorCbSet_ 监听器集合；CallOnScreenCaptureStarted/Finished 通知 | 全局单例 |
| UIExtensionAbilityConnection | UI 扩展连接，AbilityConnectionStub | OnAbilityConnectDone/OnAbilityDisconnectDone；ConnectStatus 状态机 UNKNOWN→STARTING→STARTED→CLOSING→CLOSED；CloseDialog 关闭弹窗 | UI 扩展 |
| ScreenCaptureServiceProviders | 依赖注入实现类 | 实现 IScreenCaptureServiceProviders 接口 | 实现类 |

## 上下文与场景

### 交互流程

**屏幕录制创建流程**：

```
应用 → IPC → ScreenCaptureServiceStub::OnRemoteRequest
  → ScreenCaptureServer::Create(providers)
  → ScreenCaptureServerManager::RegisterServer(sessionId, server, appUid)
  → 返回 ScreenCaptureServiceStub (IPC 端)
```

**屏幕录制启动流程**：

```
应用 → IPC → ScreenCaptureServer::StartScreenCapture
  → RequestUserPrivacyAuthority 弹窗授权
  → MakeVirtualScreenMirror/MakeVirtualScreenExtended 创建虚拟屏幕
  → StartInnerAudioCapture/StartMicAudioCapture 启动音频采集
  → StartStreamVideoCapture/StartScreenCaptureFile 启动视频/文件录制
  → PostStartScreenCapture 后处理
```

**监听器注册流程**：

```
ScreenCaptureServer::SetupCaptureListeners
  → ScreenCaptureListenerManager::RegisterListeners(listenerFlags, params)
  → 按 ListenerFlag 位图分别注册 9 类 Wrapper
  → Wrapper 回调 → IScreenCaptureEventListener → ScreenCaptureServer
```

### 状态流转

**ScreenCaptureServer 7 状态状态机**：

| 状态 | 说明 | 允许的操作 |
|------|------|-----------|
| CREATED | 已创建 | Init/配置参数 |
| POPUP_WINDOW | 弹窗中 | 等待用户授权 |
| STARTING | 启动中 | 等待虚拟屏幕/音频/视频就绪 |
| STARTED | 已启动 | StopScreenCapture/PauseScreenCapture |
| PAUSED | 已暂停 | ResumeScreenCapture/StopScreenCapture |
| RESUMED | 已恢复 | StopScreenCapture/PauseScreenCapture |
| STOPPED | 已停止 | Release |

### 状态-能力映射

| Capability 位 | 说明 |
|---------------|------|
| CAP_NONE | 无能力 |
| CAP_INIT | 已初始化 |
| CAP_CONFIG | 已配置 |
| CAP_ALIVE | 实例存活 |
| CAP_POPUP | 弹窗中 |
| CAP_RUNNING | 录制运行中 |
| CAP_PAUSED | 已暂停 |
| CAP_ACTIVE | 活跃状态 |

### 异常处理路径

| 异常场景 | 处理方式 |
|---------|---------|
| 用户拒绝隐私授权 | StopScreenCaptureByEvent(SCREEN_CAPTURE_STATE_CANCELED)，StopReason=REQUEST_USER_PRIVACY_AUTHORITY_FAILED |
| 虚拟屏幕创建失败 | PostStartScreenCaptureFail，StopReason=POST_START_SCREENCAPTURE_HANDLE_FAILURE |
| 通话中断 | OnCallStateChanged → TelCallStateUpdated，可选 keepCaptureDuringCall 策略 |
| 隐私窗口出现 | OnPrivateWindowChange → 虚拟屏幕黑屏处理 |
| 账号切换 | OnAccountSwitched → 停止录制并释放资源 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 实例限制 | maxAppLimit_=4（全局最多 4 个实例），maxSessionPerUid_=4（每 UID 最多 4 会话），maxSCServerDataTypePerUid_=2（每 UID 最多 2 种数据类型），maxSessionId_=16（会话 ID 上限） |
| 业务规则 | ScreenCaptureServer 所有操作经过能力位图校验，IsState(cap) 检查当前状态能力 |
| 性能约束 | 所有录制操作通过 TaskQueue 异步执行，IPC 线程快速返回不阻塞 |
| 安全与隐私约束 | 屏幕录制需用户隐私授权弹窗（UIExtensionAbilityConnection），授权后方可采集 |
| 线程安全 | mutex_/captureIdsMutex_/captureConfigMutex_(shared_mutex) 保护状态/配置/ID |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上层依赖 | [[ipc-layer-entities]] — 通过 IPC 存根/代理接收客户端请求 |
| 下游影响 | [[capture-implementation]] — 虚拟屏幕/音频采集/文件录制 |
| 平级关联 | ScreenCaptureServer ↔ ScreenCaptureListenerManager — 前者实现事件监听接口，后者管理监听器注册 |
| 概念对比 | ScreenCaptureServer vs ScreenCaptureMonitorServer — 前者管理单个录制实例，后者全局监控 |

## 数据模型

### StatisticalEventInfo

DFX 统计事件信息结构体：

| 字段 | 说明 |
|------|------|
| errCode / errMsg | 错误码与错误信息 |
| captureDuration | 录制时长 |
| userAgree | 用户是否同意 |
| requireMic / enableMic | 需要麦克风/已启用麦克风 |
| videoResolution | 视频分辨率 |
| stopReason | 停止原因 |
| startLatency | 启动延迟 |

### ScreenCaptureServerManager 数据结构

| 数据结构 | 说明 |
|---------|------|
| serverMap_ | map\<sessionId, ServerEntry\> — 会话 ID → 服务器实例映射 |
| ServerEntry | server(weak_ptr) + appUid + dataType |
| saUidAppUidMap_ | map\<saUid, pair\<appUid, curAppUid\>\> — SA 应用映射 |

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| ScreenCaptureServer | `services/services/screen_capture/server/screen_capture_server.h/.cpp` | ScreenCaptureServer::StartScreenCapture/StopScreenCapture/PauseScreenCapture |
| ScreenCaptureServerBase | `services/services/screen_capture/server/screen_capture_server_base.h` | AVScreenCaptureState, Capability, StopReason, StatisticalEventInfo |
| ScreenCaptureServerManager | `services/services/screen_capture/server/screen_capture_server_manager.h/.cpp` | ScreenCaptureServerManager::GetNewSessionId/CanScreenCaptureInstanceBeCreate |
| ScreenCaptureCallbackProxy | `services/services/screen_capture/server/screen_capture_callback_proxy.h/.cpp` | ScreenCaptureCallbackProxy::SetCallback/SetBufferActive |
| ScreenCaptureListenerManager | `services/services/screen_capture/server/screen_capture_listener_manager.h/.cpp` | ScreenCaptureListenerManager::RegisterListeners/UnregisterListeners |
| IScreenCaptureEventListener | `services/services/screen_capture/server/screen_capture_event_listener.h` | IScreenCaptureEventListener |
| IScreenCaptureServiceProviders | `services/services/screen_capture/server/screen_capture_service_providers.h/.cpp` | IScreenCaptureServiceProviders, ScreenCaptureServiceProviders |
| ScreenCaptureControllerServer | `services/services/screen_capture/server/screen_capture_controller_server.h/.cpp` | ScreenCaptureControllerServer::ReportAVScreenCaptureUserChoice |
| ScreenCaptureMonitorServer | `services/services/screen_capture_monitor/server/screen_capture_monitor_server.h/.cpp` | ScreenCaptureMonitorServer::GetInstance/CallOnScreenCaptureStarted |
| UIExtensionAbilityConnection | `services/services/screen_capture/server/ui_extension_ability_connection.h/.cpp` | UIExtensionAbilityConnection, ConnectStatus |

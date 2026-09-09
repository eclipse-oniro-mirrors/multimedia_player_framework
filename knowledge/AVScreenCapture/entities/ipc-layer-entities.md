# IPC 层实体

> ScreenCaptureClient、存根/代理、监听器等跨进程通信实体

## 实体概念

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| ScreenCaptureClient | 应用进程屏幕录制代理，持有 IPC 代理端和监听器存根 | screenCaptureProxy_ (IStandardScreenCaptureService)；listenerStub_ (ScreenCaptureListenerStub)；callback_ (ScreenCaptureCallBack)；CreateListenerObject 注册回调代理；MediaServerDied 死亡通知 | 客户端 |
| ScreenCaptureServiceProxy | IPC 调用端，序列化参数发送到服务端 | SetCaptureMode/SetDataType 序列化模式/类型；InitAudioCap/InitVideoCap 序列化采集参数；StartScreenCapture/StopScreenCapture 生命周期控制；AcquireAudioBuffer/AcquireVideoBuffer 缓冲获取；SetScreenCaptureStrategy/SetCaptureAreaHighlight 策略参数 | 客户端代理端 |
| ScreenCaptureServiceStub | IPC 服务端入口，接收请求并分发 | screenCaptureStubFuncs_ 方法映射表（消息码 → 处理函数）；SetListenerObject 注册客户端回调代理；权限校验 | 服务端存根 |
| ScreenCaptureListenerCallback | 桥接类，将 ScreenCaptureCallBack 转发到 IPC 通路 | OnError/OnAudioBufferAvailable/OnVideoBufferAvailable/OnStateChange/OnDisplaySelected/OnCaptureContentChanged/OnUserSelected/OnPrivacyProtect 8 个回调桥接；持有 listenerProxy_ (IStandardScreenCaptureListener 代理端) | 回调通路 |
| ScreenCaptureListenerProxy | 服务端回调代理端，序列化事件发送到客户端 | OnError/OnAudioBufferAvailable 等 8 个回调序列化发送 | 回调通路代理端 |
| ScreenCaptureListenerStub | 客户端回调接收端，反序列化事件并调用应用层回调 | OnRemoteRequest 接收回调并按类型分发；反序列化参数后转发到 ScreenCaptureCallBack | 回调通路存根 |
| IStandardScreenCaptureService | 客户端→服务端 屏幕录制控制接口，41 个消息码 | SetCaptureMode/SetDataType/SetRecorderInfo 配置；InitAudioCap/InitVideoCap/InitAudioEncInfo/InitVideoEncInfo 初始化；StartScreenCapture/StopScreenCapture/PauseScreenCapture/ResumeScreenCapture 生命周期；AcquireAudioBuffer/AcquireVideoBuffer/ReleaseAudioBuffer/ReleaseVideoBuffer 缓冲管理；SetScreenCaptureStrategy/UpdateSurface/SetCaptureArea 策略 | IPC 接口定义 |
| IStandardScreenCaptureListener | 服务端→客户端 事件通知接口，8 个消息码 | OnError/OnAudioBufferAvailable/OnVideoBufferAvailable/OnStateChange/OnDisplaySelected/OnCaptureContentChanged/OnUserSelected/OnPrivacyProtect | IPC 接口定义 |
| ScreenCaptureControllerClient | 用户选择控制器客户端 | screenCaptureControllerProxy_ (IStandardScreenCaptureController)；ReportAVScreenCaptureUserChoice/GetAVScreenCaptureConfigurableParameters 透传；MediaServerDied | 客户端 |
| ScreenCaptureControllerStub | Controller 服务端入口 | screenCaptureControllerStubFuncs_ 映射表；ReportAVScreenCaptureUserChoice/GetAVScreenCaptureConfigurableParameters/DestroyStub | 服务端存根 |
| ScreenCaptureControllerProxy | Controller 客户端代理端 | ReportAVScreenCaptureUserChoice/GetAVScreenCaptureConfigurableParameters/DestroyStub 序列化 | 客户端代理端 |
| IStandardScreenCaptureController | 用户选择控制接口，3 个消息码 | REPORT_USER_CHOICE/GET_CONFIG_PARAM/DESTROY | IPC 接口定义 |
| ScreenCaptureMonitorClient | Monitor 客户端 | screenCaptureMonitorProxy_ (IStandardScreenCaptureMonitorService)；listenerStub_ (ScreenCaptureMonitorListenerStub)；screenCaptureMonitorClientCallbacks_ 回调集合 | 客户端 |
| ScreenCaptureMonitorServiceStub | Monitor 服务端入口 | screenCaptureMonitorStubFuncs_ 映射表；SetListenerObject/IsScreenCaptureWorking/IsSystemScreenRecorder | 服务端存根 |
| ScreenCaptureMonitorServiceProxy | Monitor 客户端代理端 | IsScreenCaptureWorking/IsSystemScreenRecorder/IsSystemScreenRecorderWorking 序列化 | 客户端代理端 |
| IStandardScreenCaptureMonitorService | Monitor 控制接口，6 个消息码 | SET_LISTENER_OBJ/IS_SCREEN_CAPTURE_WORKING/DESTROY/CLOSE_LISTENER_OBJ/IS_SYSTEM_SCREEN_RECORDER/IS_SYSTEM_SCREEN_RECORDER_WORKING | IPC 接口定义 |
| IStandardScreenCaptureMonitorListener | Monitor 回调接口，3 个消息码 | ON_SCREEN_CAPTURE_STARTED/ON_SCREEN_CAPTURE_FINISHED/ON_SCREEN_CAPTURE_DIED | IPC 接口定义 |
| ScreenCaptureMonitorListenerStub | Monitor 客户端回调接收端 | OnScreenCaptureStarted/OnScreenCaptureFinished/OnScreenCaptureDied 反序列化转发；screenCaptureMonitorCallbacks_ 回调集合 | 回调通路存根 |
| ScreenCaptureMonitorListenerProxy | Monitor 服务端回调代理端 | OnScreenCaptureStarted/OnScreenCaptureFinished/OnScreenCaptureDied 序列化发送 | 回调通路代理端 |
| ScreenCaptureMonitorListenerCallback | Monitor 桥接类 | ScreenCaptureMonitor::ScreenCaptureMonitorListener → IPC 转发 | 回调桥接 |

## 上下文与场景

### 交互流程

**IPC 调用通路（客户端 → 服务端）**：

```
应用调用 → ScreenCaptureClient → ScreenCaptureServiceProxy (序列化)
  → IPC Binder → ScreenCaptureServiceStub (反序列化 + 分发)
  → ScreenCaptureServer 处理
```

**IPC 回调通路（服务端 → 客户端）**：

```
服务端事件 → ScreenCaptureCallbackProxy (服务端内部回调代理)
  → ScreenCaptureListenerCallback (桥接)
  → ScreenCaptureListenerProxy (序列化)
  → IPC Binder → ScreenCaptureListenerStub (反序列化)
  → 应用层 ScreenCaptureCallBack
```

**Monitor 回调通路（服务端 → 客户端）**：

```
ScreenCaptureMonitorServer::CallOnScreenCaptureStarted
  → ScreenCaptureMonitorListenerProxy (序列化)
  → IPC Binder → ScreenCaptureMonitorListenerStub (反序列化)
  → 应用层 ScreenCaptureMonitorListener
```

### 角色与参与方

| 角色 | 职责 |
|------|------|
| ScreenCaptureClient | 应用进程代理，转发调用 + 接收回调 |
| ScreenCaptureServiceProxy | 序列化参数，发起 IPC 调用 |
| ScreenCaptureServiceStub | 反序列化请求，分发到 ScreenCaptureServer |
| ScreenCaptureListenerCallback | 桥接 ScreenCaptureCallBack → IPC |
| ScreenCaptureListenerProxy | 序列化事件，发起 IPC 回调 |
| ScreenCaptureListenerStub | 反序列化事件，调用应用回调 |
| ScreenCaptureMonitorClient | Monitor 客户端代理 |
| ScreenCaptureMonitorServiceStub | Monitor 服务端入口 |
| ScreenCaptureMonitorListenerProxy/Stub | Monitor 回调双向代理 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 系统限制 | IPC 传输数据必须通过 MessageParcel 序列化，不可共享裸指针 |
| 业务规则 | Surface 通过序列号传递，不直接跨进程共享 Surface 对象 |
| 业务规则 | ScreenCaptureCallbackProxy 使用 shared_mutex 保护回调，SetBufferActive 控制缓冲回调开关 |
| 安全与隐私约束 | ScreenCaptureServiceStub 检查调用方权限 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上层依赖 | [[api-layer]] — ScreenCaptureImpl 持有 ScreenCaptureClient 发起 IPC |
| 下游影响 | [[service-layer]] — ScreenCaptureServiceStub 分发请求到 ScreenCaptureServer |
| 平级关联 | ScreenCaptureServiceProxy ↔ ScreenCaptureListenerProxy — 前者负责调用通路，后者负责回调通路 |
| 概念对比 | IStandardScreenCaptureService (调用接口) vs IStandardScreenCaptureListener (回调接口) — 双向 IPC 的两个方向 |

## 数据模型

### IStandardScreenCaptureService 消息码表（41 个）

| 消息码 | 值 | 说明 |
|--------|---|------|
| SET_LISTENER_OBJ | 0 | 注册回调代理 |
| RELEASE | 1 | 释放 |
| DESTROY | 2 | 销毁存根 |
| SET_CAPTURE_MODE | 3 | 设置采集模式 |
| SET_DATA_TYPE | 4 | 设置数据类型 |
| SET_RECORDER_INFO | 5 | 设置录制信息 |
| SET_OUTPUT_FILE | 6 | 设置输出文件 |
| INIT_AUDIO_ENC_INFO | 7 | 初始化音频编码信息 |
| INIT_AUDIO_CAP | 8 | 初始化音频采集参数 |
| INIT_VIDEO_ENC_INFO | 9 | 初始化视频编码信息 |
| INIT_VIDEO_CAP | 10 | 初始化视频采集参数 |
| ACQUIRE_AUDIO_BUF | 11 | 获取音频缓冲 |
| ACQUIRE_VIDEO_BUF | 12 | 获取视频缓冲 |
| RELEASE_AUDIO_BUF | 13 | 释放音频缓冲 |
| RELEASE_VIDEO_BUF | 14 | 释放视频缓冲 |
| SET_MIC_ENABLE | 15 | 设置麦克风开关 |
| START_SCREEN_CAPTURE | 16 | 启动屏幕采集 |
| START_SCREEN_CAPTURE_WITH_SURFACE | 17 | 带 Surface 启动屏幕采集 |
| STOP_SCREEN_CAPTURE | 18 | 停止屏幕采集 |
| SET_SCREEN_ROTATION | 19 | 设置屏幕旋转 |
| EXCLUDE_CONTENT | 20 | 排除内容 |
| RESIZE_CANVAS | 21 | 调整画布 |
| SKIP_PRIVACY | 22 | 跳过隐私模式 |
| SET_MAX_FRAME_RATE | 23 | 设置最大帧率 |
| SHOW_CURSOR | 24 | 显示光标 |
| SET_CHECK_SA_LIMIT | 25 | 设置检查 SA 限制 |
| SET_CHECK_LIMIT | 26 | 设置检查限制 |
| SET_STRATEGY | 27 | 设置策略 |
| UPDATE_SURFACE | 28 | 更新 Surface |
| SET_CAPTURE_AREA | 29 | 设置采集区域 |
| SET_HIGH_LIGHT_MODE | 30 | 设置高亮模式 |
| PRESENT_PICKER | 31 | 弹出选择器 |
| EXCLUDE_PICKER_WINDOWS | 32 | 排除选择器窗口 |
| SET_PICKER_MODE | 33 | 设置选择器模式 |
| ADD_WHITE_LIST_WINDOWS | 34 | 添加白名单窗口 |
| REMOVE_WHITE_LIST_WINDOWS | 35 | 移除白名单窗口 |
| GET_MULTI_DISPLAY_CAPTURE_CAPABILITY | 36 | 获取多屏采集能力 |
| PAUSE_SCREEN_CAPTURE | 37 | 暂停屏幕采集 |
| RESUME_SCREEN_CAPTURE | 38 | 恢复屏幕采集 |
| ADD_WATERMARK | 39 | 添加水印 |
| SET_CONTENT_AUTO_ROTATION | 40 | 设置内容自动旋转 |

### IStandardScreenCaptureListener 消息码表（8 个）

| 消息码 | 值 | 说明 |
|--------|---|------|
| ON_ERROR | 0 | 错误回调 |
| ON_AUDIO_AVAILABLE | 1 | 音频缓冲就绪 |
| ON_VIDEO_AVAILABLE | 2 | 视频缓冲就绪 |
| ON_STAGE_CHANGE | 3 | 状态变更 |
| ON_DISPLAY_SELECTED | 4 | 显示选择 |
| ON_CONTENT_CHANGED | 5 | 内容变更 |
| ON_USER_SELECTED | 6 | 用户选择 |
| ON_PRIVACY_PROTECT | 7 | 隐私保护 |

### IStandardScreenCaptureController 消息码表（3 个）

| 消息码 | 值 | 说明 |
|--------|---|------|
| REPORT_USER_CHOICE | 0 | 上报用户选择 |
| GET_CONFIG_PARAM | 1 | 获取配置参数 |
| DESTROY | 2 | 销毁存根 |

### IStandardScreenCaptureMonitorService 消息码表（6 个）

| 消息码 | 值 | 说明 |
|--------|---|------|
| SET_LISTENER_OBJ | 0 | 注册回调代理 |
| IS_SCREEN_CAPTURE_WORKING | 1 | 查询运行中 PID |
| DESTROY | 2 | 销毁存根 |
| CLOSE_LISTENER_OBJ | 3 | 关闭回调代理 |
| IS_SYSTEM_SCREEN_RECORDER | 4 | 查询系统录制器 |
| IS_SYSTEM_SCREEN_RECORDER_WORKING | 5 | 查询系统录制器是否运行 |

### IStandardScreenCaptureMonitorListener 消息码表（3 个）

| 消息码 | 值 | 说明 |
|--------|---|------|
| ON_SCREEN_CAPTURE_STARTED | 1 | 屏幕录制开始 |
| ON_SCREEN_CAPTURE_FINISHED | 2 | 屏幕录制结束 |
| ON_SCREEN_CAPTURE_DIED | 3 | 屏幕录制进程死亡 |

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| IStandardScreenCaptureService | `services/services/screen_capture/ipc/i_standard_screen_capture_service.h` | IStandardScreenCaptureService, ScreenCaptureServiceMsg |
| IStandardScreenCaptureListener | `services/services/screen_capture/ipc/i_standard_screen_capture_listener.h` | IStandardScreenCaptureListener, ScreenCaptureListenerMsg |
| IStandardScreenCaptureController | `services/services/screen_capture/ipc/i_standard_screen_capture_controller.h` | IStandardScreenCaptureController, ScreenCaptureControllerMsg |
| ScreenCaptureServiceStub | `services/services/screen_capture/ipc/screen_capture_service_stub.h/.cpp` | ScreenCaptureServiceStub, screenCaptureStubFuncs_ |
| ScreenCaptureServiceProxy | `services/services/screen_capture/ipc/screen_capture_service_proxy.h/.cpp` | ScreenCaptureServiceProxy |
| ScreenCaptureListenerCallback | `services/services/screen_capture/ipc/screen_capture_listener_callback.h/.cpp` | ScreenCaptureListenerCallback |
| ScreenCaptureListenerProxy | `services/services/screen_capture/ipc/screen_capture_listener_proxy.h/.cpp` | ScreenCaptureListenerProxy |
| ScreenCaptureListenerStub | `services/services/screen_capture/ipc/screen_capture_listener_stub.h/.cpp` | ScreenCaptureListenerStub |
| ScreenCaptureClient | `services/services/screen_capture/client/screen_capture_client.h/.cpp` | ScreenCaptureClient, CreateListenerObject |
| ScreenCaptureControllerStub | `services/services/screen_capture/ipc/screen_capture_controller_stub.h/.cpp` | ScreenCaptureControllerStub |
| ScreenCaptureControllerProxy | `services/services/screen_capture/ipc/screen_capture_controller_proxy.h/.cpp` | ScreenCaptureControllerProxy |
| ScreenCaptureControllerClient | `services/services/screen_capture/client/screen_capture_controller_client.h/.cpp` | ScreenCaptureControllerClient |
| IStandardScreenCaptureMonitorService | `services/services/screen_capture_monitor/ipc/i_standard_screen_capture_monitor_service.h` | IStandardScreenCaptureMonitorService |
| IStandardScreenCaptureMonitorListener | `services/services/screen_capture_monitor/ipc/i_standard_screen_capture_monitor_listener.h` | IStandardScreenCaptureMonitorListener |
| ScreenCaptureMonitorServiceStub | `services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_stub.h/.cpp` | ScreenCaptureMonitorServiceStub |
| ScreenCaptureMonitorServiceProxy | `services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_proxy.h/.cpp` | ScreenCaptureMonitorServiceProxy |
| ScreenCaptureMonitorListenerStub | `services/services/screen_capture_monitor/ipc/screen_capture_monitor_listener_stub.h/.cpp` | ScreenCaptureMonitorListenerStub |
| ScreenCaptureMonitorListenerProxy | `services/services/screen_capture_monitor/ipc/screen_capture_monitor_listener_proxy.h/.cpp` | ScreenCaptureMonitorListenerProxy, ScreenCaptureMonitorListenerCallback |
| ScreenCaptureMonitorClient | `services/services/screen_capture_monitor/client/screen_capture_monitor_client.h/.cpp` | ScreenCaptureMonitorClient |

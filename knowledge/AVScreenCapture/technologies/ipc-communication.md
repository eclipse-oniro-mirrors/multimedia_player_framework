# IPC 通信与回调机制

> Client-Server 通信架构、回调链路、异常恢复。录屏框架通过多组 IPC 接口实现应用与媒体服务进程间的双向通信。

## 一、IPC 通信架构

录屏框架采用 **Client-Server 双进程架构**，通过 OHOS IPC (Binder) 通信：

```
应用进程                                媒体服务进程
┌──────────────────────────┐          ┌───────────────────────────────────┐
│ ScreenCaptureClient      │          │ ScreenCaptureServiceStub          │
│   └─proxy_ ─────────────│── IPC ──→│   └─转发给 ScreenCaptureServer    │
│                          │          │                                   │
│ ScreenCaptureCallBack    │← IPC ────│ ScreenCaptureListenerProxy        │
│   └─应用层回调            │          │   └─事件推送                      │
│                          │          │                                   │
│ ScreenCaptureControllerClient│       │ ScreenCaptureControllerStub       │
│   └─proxy_ ─────────────│── IPC ──→│   └─转发给 ScreenCaptureControllerServer│
│                          │          │                                   │
│ ScreenCaptureMonitorClient│         │ ScreenCaptureMonitorServiceStub   │
│   └─proxy_ ─────────────│── IPC ──→│   └─转发给 MonitorServer          │
│                          │          │                                   │
│ MonitorListener          │← IPC ────│ MonitorListenerProxy              │
│   └─监听回调              │          │   └─事件推送                      │
└──────────────────────────┘          └───────────────────────────────────┘
```

### 1.1 调用通路（Client → Server）

```
应用 → ScreenCaptureClient::StartScreenCapture()
  → ScreenCaptureServiceProxy::StartScreenCapture()       ← 序列化参数
  → IPC Binder 驱动
  → ScreenCaptureServiceStub::OnRemoteRequest()            ← 反序列化
  → ScreenCaptureServer::StartScreenCapture()              ← 执行业务逻辑
```

### 1.2 回调通路（Server → Client）

```
ScreenCaptureServer → ScreenCaptureCallbackProxy::OnStateChange()
  → ScreenCaptureListenerCallback::OnStateChange()
  → ScreenCaptureListenerProxy::OnStateChange()           ← 序列化事件
  → IPC Binder 驱动
  → ScreenCaptureListenerStub::OnRemoteRequest()          ← 反序列化
  → ScreenCaptureCallBack::OnStateChange()                 ← 应用层回调
```

## 二、IPC 接口定义

### 2.1 IStandardScreenCaptureService（调用接口，41 个消息码）

Client → Server 的录屏控制接口：

| 消息码 | 枚举 | 方法 | 说明 |
|--------|------|------|------|
| 0 | SET_LISTENER_OBJ | SetListenerObject | 设置回调监听对象 |
| 1 | RELEASE | Release | 释放实例 |
| 2 | DESTROY | DestroyStub | 销毁 Stub |
| 3 | SET_CAPTURE_MODE | SetCaptureMode | 设置采集模式 |
| 4 | SET_DATA_TYPE | SetDataType | 设置数据类型 |
| 5 | SET_RECORDER_INFO | SetRecorderInfo | 设置录制信息 |
| 6 | SET_OUTPUT_FILE | SetOutputFile | 设置输出文件 |
| 7 | INIT_AUDIO_ENC_INFO | InitAudioEncInfo | 初始化音频编码 |
| 8 | INIT_AUDIO_CAP | InitAudioCap | 初始化音频采集 |
| 9 | INIT_VIDEO_ENC_INFO | InitVideoEncInfo | 初始化视频编码 |
| 10 | INIT_VIDEO_CAP | InitVideoCap | 初始化视频采集 |
| 11 | ACQUIRE_AUDIO_BUF | AcquireAudioBuffer | 获取音频缓冲 |
| 12 | ACQUIRE_VIDEO_BUF | AcquireVideoBuffer | 获取视频缓冲 |
| 13 | RELEASE_AUDIO_BUF | ReleaseAudioBuffer | 释放音频缓冲 |
| 14 | RELEASE_VIDEO_BUF | ReleaseVideoBuffer | 释放视频缓冲 |
| 15 | SET_MIC_ENABLE | SetMicrophoneEnabled | 麦克风开关 |
| 16 | START_SCREEN_CAPTURE | StartScreenCapture | 启动录屏 |
| 17 | START_SCREEN_CAPTURE_WITH_SURFACE | StartScreenCaptureWithSurface | 启动录屏（Surface 模式） |
| 18 | STOP_SCREEN_CAPTURE | StopScreenCapture | 停止录屏 |
| 19 | SET_SCREEN_ROTATION | SetCanvasRotation | 画布旋转 |
| 20 | EXCLUDE_CONTENT | ExcludeContent | 内容过滤 |
| 21 | RESIZE_CANVAS | ResizeCanvas | 画布调整 |
| 22 | SKIP_PRIVACY | SkipPrivacyMode | 跳过隐私窗口 |
| 23 | SET_MAX_FRAME_RATE | SetMaxVideoFrameRate | 帧率控制 |
| 24 | SHOW_CURSOR | ShowCursor | 光标显示 |
| 25 | SET_CHECK_SA_LIMIT | SetAndCheckSaLimit | SA 限制检查 |
| 26 | SET_CHECK_LIMIT | SetAndCheckLimit | 实例限制检查 |
| 27 | SET_STRATEGY | SetScreenCaptureStrategy | 策略配置 |
| 28 | UPDATE_SURFACE | UpdateSurface | 更新 Surface |
| 29 | SET_CAPTURE_AREA | SetCaptureArea | 采集区域 |
| 30 | SET_HIGH_LIGHT_MODE | SetCaptureAreaHighlight | 高亮区域 |
| 31 | PRESENT_PICKER | PresentPicker | 弹出 Picker |
| 32 | EXCLUDE_PICKER_WINDOWS | ExcludePickerWindows | 排除 Picker 窗口 |
| 33 | SET_PICKER_MODE | SetPickerMode | Picker 模式设置 |
| 34 | ADD_WHITE_LIST_WINDOWS | AddWhiteListWindows | 添加白名单窗口 |
| 35 | REMOVE_WHITE_LIST_WINDOWS | RemoveWhiteListWindows | 移除白名单窗口 |
| 36 | GET_MULTI_DISPLAY_CAPTURE_CAPABILITY | GetMultiDisplayCaptureCapability | 多屏能力查询 |
| 37 | PAUSE_SCREEN_CAPTURE | PauseScreenCapture | 暂停录屏 |
| 38 | RESUME_SCREEN_CAPTURE | ResumeScreenCapture | 恢复录屏 |
| 39 | ADD_WATERMARK | AddWatermark | 添加水印 |
| 40 | SET_CONTENT_AUTO_ROTATION | SetContentAutoRotation | 内容自动旋转 |

### 2.2 IStandardScreenCaptureListener（回调接口，8 个消息码）

Server → Client 的事件通知接口：

| 消息码 | 枚举 | 方法 | 说明 |
|--------|------|------|------|
| 0 | ON_ERROR | OnError | 错误通知 |
| 1 | ON_AUDIO_AVAILABLE | OnAudioBufferAvailable | 音频缓冲就绪 |
| 2 | ON_VIDEO_AVAILABLE | OnVideoBufferAvailable | 视频缓冲就绪 |
| 3 | ON_STAGE_CHANGE | OnStateChange | 状态变化 |
| 4 | ON_DISPLAY_SELECTED | OnDisplaySelected | 显示屏选择 |
| 5 | ON_CONTENT_CHANGED | OnCaptureContentChanged | 内容变更 |
| 6 | ON_USER_SELECTED | OnUserSelected | 用户选择 |
| 7 | ON_PRIVACY_PROTECT | OnPrivacyProtect | 隐私保护 |

### 2.3 IStandardScreenCaptureController（3 个消息码）

| 消息码 | 枚举 | 方法 | 说明 |
|--------|------|------|------|
| 0 | REPORT_USER_CHOICE | ReportAVScreenCaptureUserChoice | 上报用户选择 |
| 1 | GET_CONFIG_PARAM | GetAVScreenCaptureConfigurableParameters | 获取可配置参数 |
| 2 | DESTROY | DestroyStub | 销毁 Stub |

### 2.4 Monitor IPC 接口

**IStandardScreenCaptureMonitorService**（6 个消息码）：

| 消息码 | 方法 | 说明 |
|--------|------|------|
| 0 | SetListenerObject | 设置监听对象 |
| 1 | IsScreenCaptureWorking | 查询录屏中的 PID 列表 |
| 2 | DestroyStub | 销毁 Stub |
| 3 | CloseListenerObject | 关闭监听对象 |
| 4 | IsSystemScreenRecorder | 判断是否系统录屏器 |
| 5 | IsSystemScreenRecorderWorking | 系统录屏器是否工作中 |

**IStandardScreenCaptureMonitorListener**（3 个消息码）：

| 消息码 | 枚举 | 方法 | 说明 |
|--------|------|------|------|
| 1 | ON_SCREEN_CAPTURE_STARTED | OnScreenCaptureStarted | 录屏开始通知 |
| 2 | ON_SCREEN_CAPTURE_FINISHED | OnScreenCaptureFinished | 录屏结束通知 |
| 3 | ON_SCREEN_CAPTURE_DIED | OnScreenCaptureDied | 录屏服务死亡通知 |

## 三、回调机制详解

### 3.1 回调对象链路

```
ScreenCaptureServer
  └─ cbProxy_ (ScreenCaptureCallbackProxy)   ← 持有应用设置的 ScreenCaptureCallBack
      └─ ScreenCaptureListenerCallback（桥接类，实现 ScreenCaptureCallBack 接口）
          └─ listener_ (IStandardScreenCaptureListener.Proxy)
              └─ IPC → ScreenCaptureListenerStub
                  └─ ScreenCaptureCallBack（应用层回调）
```

### 3.2 关键回调事件表

| 事件 | 触发点 | 状态码 |
|------|--------|--------|
| SCREEN_CAPTURE_STATE_STARTED | PostStartScreenCaptureSuccessAction | STARTED |
| SCREEN_CAPTURE_STATE_CANCELED | OnReceiveUserPrivacyAuthority(DENY) | 用户拒绝授权 |
| SCREEN_CAPTURE_STATE_STOPPED_BY_USER | 通知栏 STOP 按钮 | 通知栏停止 |
| SCREEN_CAPTURE_STATE_STOPPED_BY_CALL | OnCallStateChanged | 通话打断 |
| SCREEN_CAPTURE_STATE_STOPPED_BY_USER_SWITCHES | OnAccountSwitched | 账户切换 |
| SCREEN_CAPTURE_STATE_PAUSED_BY_APP/USER | PauseScreenCapture | 暂停 |
| SCREEN_CAPTURE_STATE_RESUMED_BY_APP/USER | ResumeScreenCapture | 恢复 |
| SCREEN_CAPTURE_STATE_ENTER_PRIVATE_SCENE | OnPrivateWindowChange(true) | 隐私窗口出现 |
| SCREEN_CAPTURE_STATE_EXIT_PRIVATE_SCENE | OnPrivateWindowChange(false) | 隐私窗口消失 |
| SCREEN_CAPTURE_STATE_MIC_MUTED/UNMUTED_BY_USER | SetMicrophoneEnabled | 麦克风开关 |
| SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE | StartMicAudioCapture 失败 | 麦克风不可用 |

### 3.3 回调线程

- **服务端回调**：在引擎工作线程或事件监听线程上触发，通过 `taskQue_` 异步入队后执行
- **客户端回调**：在 IPC Binder 线程上接收，调用应用层 ScreenCaptureCallBack
- **重要约束**：应用层回调中不应执行耗时操作，否则会阻塞 IPC 线程

## 四、IPC 异常恢复

### 4.1 服务端死亡检测

```
ScreenCaptureClient 注册 DeathRecipient
  → 服务端进程死亡 → DeathRecipient::OnRemoteDied()
  → 通知应用层 SCREEN_CAPTURE_ERR_SERVICE_DIED
  → 应用可选择重建录屏实例
```

### 4.2 客户端死亡清理

```
ScreenCaptureServiceStub 监控客户端生命周期
  → 客户端进程死亡 → Stub 清理对应 ScreenCaptureServer 实例
  → ReleaseInner() → 释放虚拟屏幕/AudioCapturer/Recorder 资源
  → ScreenCaptureServerManager::RemoveScreenCaptureServerMap(sessionId)
```

### 4.3 SceneSessionManager 死亡监听

```
ScreenCaptureListenerManager 注册 SceneSessionManager DeathRecipient
  → OnSceneSessionManagerDied → 清理 windowLifecycleListener_
  → 防止 SessionManager 死亡后悬空引用
```

## 五、IPC 序列化与 Surface 传递

### 5.1 Surface 传递机制

Surface 不直接通过 IPC 序列化传递，而是通过 Surface 序列号在服务端重建：

```
应用层 Surface → WriteSurface 序列号 → IPC → 服务端 ReadSurface → 重建 Surface 对象
```

`StartScreenCaptureWithSurface` 和 `UpdateSurface` 均通过此方式传递 Surface。

### 5.2 复杂对象序列化

| 对象 | 序列化方式 |
|------|-----------|
| AVScreenCaptureConfig | 拆分为各 Set 方法逐项 IPC 传递 |
| ScreenCaptureContentFilter | filteredAudioContents + windowIDsVec |
| ScreenCaptureStrategy | 整体序列化 |
| ScreenCaptureUserSelectionInfo | selectType + displayIds |
| AVScreenCaptureHighlightConfig | lineThickness + lineColor + mode |

## 知识关联

- [[capture-lifecycle]] - 录屏完整生命周期
- [[privacy-and-permission]] - 隐私保护与权限机制
- [[design-patterns]] - 设计模式与架构解耦
- [[flows]] - 关键流程详解
- [[error-handling-and-dfx]] - 错误处理与 DFX 诊断

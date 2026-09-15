# 录屏完整生命周期

> 从创建到销毁的全流程，包含状态机、能力位图、授权弹窗、数据模式。开发核心参考。

## 一、7 状态状态机

ScreenCaptureServer 采用 **7 状态有限状态机** 管理生命周期，通过**能力位图**替代 AVPlayer 的状态类继承体系：

```
   Init(config)
   CREATED ─────────────────────→ POPUP_WINDOW
     ↑                                │
     │                  OnReceiveUserPrivacyAuthority(DENY)
     │ ←───────────────────────────── │
     │                                │ OnReceiveUserPrivacyAuthority(ALLOW)
     │                                ↓
     │                            STARTING
     │                                │ OnStartScreenCapture 成功
     │                                ↓
     │            Pause            STARTED ←──┐
     │              │                │       │ Resume
     │              ↓                │       │
     │            PAUSED ←───────────┘       │
     │              │                        │
     │              │ Resume                 │
     │              └──────────────────────→ RESUMED
     │                                        │
     │            StopScreenCapture           │
     └──────────────────────────────────── STOPPED
     
     POPUP_WINDOW/STARTING/STARTED/PAUSED/RESUMED ──OnError/Stop──→ STOPPED
```

### 状态说明

| 状态 | 枚举值 | 含义 | 允许的操作 |
|------|--------|------|-----------|
| CREATED | 0 | 初始/配置态 | Init 各配置项、SetScreenCaptureCallback、StartScreenCapture |
| POPUP_WINDOW | 1 | 授权弹窗等待中 | 等待用户 ALLOW/DENY |
| STARTING | 2 | 正在启动采集 | 无（等待启动完成） |
| STARTED | 3 | 录屏进行中 | Pause、Stop、AcquireAudio/VideoBuffer、SetMicrophoneEnabled 等 |
| PAUSED | 4 | 暂停 | Resume、Stop |
| RESUMED | 5 | 恢复 | Pause、Stop、AcquireAudio/VideoBuffer |
| STOPPED | 6 | 已停止 | Release、StartScreenCapture（重新开始） |

### 能力位图机制

每个状态对应一组 Capability 位，`IsState(cap)` 通过位与判断当前状态是否允许某操作：

```cpp
enum Capability : uint32_t {
    CAP_NONE   = 0,
    CAP_INIT   = 1 << 0,  // 允许初始化/启动
    CAP_CONFIG = 1 << 1,  // 允许配置
    CAP_ALIVE  = 1 << 2,  // 实例存活（非STOPPED前的清理态）
    CAP_POPUP  = 1 << 4,  // 弹窗态
    CAP_RUNNING= 1 << 5,  // 运行态
    CAP_PAUSED = 1 << 6,  // 暂停态
    CAP_ACTIVE = 1 << 7,  // 允许 Acquire/Release Buffer
};

bool IsState(uint32_t cap) const {
    return (STATE_CAPS_[captureState_.load()] & cap) != 0;
}
```

### STATE_CAPS_ 映射表

| 状态 | 能力位 |
|------|--------|
| CREATED | `CAP_INIT \| CAP_CONFIG \| CAP_ALIVE` |
| POPUP_WINDOW | `CAP_ALIVE \| CAP_POPUP` |
| STARTING | `CAP_ALIVE` |
| STARTED | `CAP_ALIVE \| CAP_RUNNING \| CAP_ACTIVE` |
| PAUSED | `CAP_ALIVE \| CAP_PAUSED \| CAP_ACTIVE` |
| RESUMED | `CAP_ALIVE \| CAP_RUNNING \| CAP_ACTIVE` |
| STOPPED | `CAP_INIT` |

### 状态转换约束（铁律）

1. **必须配置后启动**：CREATED → POPUP_WINDOW → STARTING → STARTED
2. **Pause/Resume 可逆**：STARTED ↔ PAUSED、PAUSED → RESUMED
3. **Stop 回到 STOPPED**：任何 CAP_ALIVE 状态 → STOPPED，STOPPED 可重新 StartScreenCapture（回到 CREATED 能力）
4. **Release 不可逆**：Release 后实例销毁，不可再使用
5. **配置只在 CREATED**：SetCaptureMode/SetDataType/InitAudio*/InitVideo*/SetRecorderInfo/SetOutputFile 只在 `CAP_CONFIG` 态允许
6. **Buffer 操作只在 ACTIVE 态**：AcquireAudioBuffer/AcquireVideoBuffer/ReleaseAudioBuffer/ReleaseVideoBuffer 需要 `CAP_ACTIVE`（STARTED 或 RESUMED）

## 二、完整生命周期流程

### 2.1 创建实例

```
应用 → ScreenCaptureFactory::CreateScreenCapture()
  → ScreenCaptureImpl 创建（Native API 层）
  → MediaServiceFactory::CreateScreenCaptureService()
  → IPC → ScreenCaptureServiceStub::Create()
  → ScreenCaptureServer::Create(providers)：
    - ScreenCaptureServerManager::GetNewSessionId()
    - 构造 ScreenCaptureServer（cbProxy_ 创建、InitAppInfo、instanceId 生成、taskQue_.Start()）
    - ScreenCaptureServerManager::RegisterServer(sessionId, server, appUid)
  → 返回 ScreenCaptureClient 给应用
```

### 2.2 初始化配置

```
应用 → ScreenCapture::Init(config)
  → IPC → ScreenCaptureServer：
    - SetCaptureMode(captureMode) → 校验 CAP_CONFIG
    - SetDataType(dataType) → 校验 CAP_CONFIG
    - InitAudioEncInfo / InitAudioCap → 校验音频参数
    - InitVideoEncInfo / InitVideoCap → 校验视频参数
    - SetRecorderInfo / SetOutputFile（CAPTURE_FILE 模式）
    - SetScreenCaptureStrategy（可选）
  → 状态保持 CREATED
```

**配置项一览**：

| 配置项 | 方法 | 校验状态 |
|--------|------|---------|
| 采集模式 | SetCaptureMode | CAP_CONFIG |
| 数据类型 | SetDataType | CAP_CONFIG |
| 音频采集参数 | InitAudioCap | CAP_CONFIG |
| 音频编码参数 | InitAudioEncInfo | CAP_CONFIG |
| 视频采集参数 | InitVideoCap | CAP_CONFIG |
| 视频编码参数 | InitVideoEncInfo | CAP_CONFIG |
| 录制信息 | SetRecorderInfo | CAP_CONFIG |
| 输出文件 | SetOutputFile | CAP_CONFIG |
| 策略 | SetScreenCaptureStrategy | < POPUP_WINDOW |
| 回调 | SetScreenCaptureCallback | CAP_CONFIG |

### 2.3 启动录屏

```
应用 → StartScreenCapture(isPrivacyAuthorityEnabled)
  → IPC → ScreenCaptureServer::StartScreenCapture()
    - 校验 CAP_INIT（CREATED 或 STOPPED）
    - StartScreenCaptureInner(isPrivacyAuthorityEnabled)：
      1. PrepareStartCapture() → 注册 LF_ACCOUNT/LF_CALL 监听、CheckAllParams、获取 Display 信息
      2. captureState_ → POPUP_WINDOW
      3. CheckPrivacyWindowSkipPermission() → 判断是否免弹窗
      4. IsUserPrivacyAuthorityNeeded() → 判断是否需要用户授权（Root UID=0 免授权）
      5. 若需要授权 → RequestUserPrivacyAuthority() → StartAuthWindow() 弹出授权弹窗
         - 等待用户 ALLOW/DENY → OnReceiveUserPrivacyAuthority()
      6. 若免授权/已授权 → OnStartScreenCapture(isSkipPrivacyWindow)：
         - captureState_ → STARTING
         - ORIGINAL_STREAM → StartScreenCaptureStream()
         - CAPTURE_FILE → StartScreenCaptureFile()
      7. PostStartScreenCapture(isSuccess)：
         - 成功 → captureState_ → STARTED
         - Monitor.CallOnScreenCaptureStarted(pid)
         - cbProxy_->OnStateChange(SCREEN_CAPTURE_STATE_STARTED)
         - cbProxy_->OnDisplaySelected(displayId)
         - 注册 LF_PRIVATE_WIN/LF_SCREEN_CONN 等监听
```

### 2.4 暂停 / 恢复

```
应用 → PauseScreenCapture()
  → IPC → ScreenCaptureServer::PauseScreenCaptureInner(PAUSED_BY_APP)
    - 校验 CAP_RUNNING（STARTED 或 RESUMED）
    - 校验 strategy.enablePause == true
    - FILE 模式 → PauseRecorder()
    - PauseVideoCapture() → StopMirror / DestroyVirtualScreen
    - StopAudioCapture() → micAudioCapture_/innerAudioCapture_ Stop
    - audioSource_->Pause()
    - captureState_ → PAUSED
    - cbProxy_->OnStateChange(PAUSED_BY_APP)
    - 更新通知栏实时视图

应用 → ResumeScreenCapture()
  → IPC → ScreenCaptureServer::ResumeScreenCaptureInner(RESUMED_BY_APP)
    - 校验 CAP_PAUSED
    - 校验 strategy.enablePause == true
    - ResumeVideoCapture() → MakeVirtualScreenMirror / CreateVirtualScreen
    - SyncAudioCaptures(true)
    - audioSource_->Resume()
    - FILE 模式 → ResumeRecorder()
    - captureState_ → RESUMED
    - cbProxy_->OnStateChange(RESUMED_BY_APP)
```

### 2.5 停止录屏

```
应用 → StopScreenCapture()
  → IPC → ScreenCaptureServer::StopScreenCaptureByEvent(INVALID)
    - 若 IsState(CAP_ALIVE) → StopScreenCaptureInner(stateCode)：
      1. cbProxy_->SetBufferActive(false)
      2. 若 CAP_ALIVE 但非 CAP_ACTIVE → StopNotStartedScreenCapture()
      3. CAPTURE_FILE → StopScreenCaptureRecorder()
         ORIGINAL_STREAM → StopAudioAndVideoCapture()
      4. PostStopScreenCapture(stateCode)：
         - Monitor.CallOnScreenCaptureFinished(pid)
         - cbProxy_->OnStateChange(stateCode)
         - LastPidUpdatePrivacyUsingPermissionState(STOP_VIDEO)
         - captureState_ → STOPPED
      5. listenerManager_->UnregisterListeners()
```

### 2.6 释放

```
应用 → Release()
  → ScreenCaptureServer::ReleaseInner()
    - 若 IsState(CAP_ALIVE) → StopScreenCaptureInner(INVALID)
    - skipPrivacyWindowIDsVec_.clear()
    - ScreenCaptureServerManager::RemoveSaAppInfoMap(saUid_)
    - sessionId_ = -1
    - SetMetaDataReport() → HiSysEvent 上报统计数据
    - ScreenCaptureServerManager::RemoveScreenCaptureServerMap(sessionId)
    - taskQue_.Stop()
    - CloseFd()
  → g_serverMap.erase(ptr) → 析构
```

## 三、两种数据模式

| 模式 | DataType | 数据获取方式 | 说明 |
|------|----------|-------------|------|
| 原始流 | ORIGINAL_STREAM | AcquireAudioBuffer/AcquireVideoBuffer | 应用直接获取原始 PCM/YUV 帧 |
| 文件录制 | CAPTURE_FILE | Recorder 引擎编码封装 | 复用 IRecorderService，AudioDataSource 提供混音音频，Surface 提供视频 |

**原始流模式**中还有 Surface 模式（`StartScreenCaptureWithSurface`），应用传入自定义 Surface 直接接收视频帧。

## 四、授权流程

```
StartScreenCaptureInner
  ├── IsUserPrivacyAuthorityNeeded()
  │     ├── appUid == ROOT_UID(0) → false（Root 自动授权）
  │     └── 其它 → true（需要授权）
  ├── CheckPrivacyWindowSkipPermission()
  │     └── 验证 ohos.permission.EXEMPT_CAPTURE_SCREEN_AUTHORIZE
  ├── IsSkipPrivacyWindow()
  │     └── isSystemRecorder || (CheckCustScrRecPermission && !IsPickerPopUp)
  │           → 系统录屏器 或 自定义录屏权限+Picker未弹出 → 跳过弹窗
  └── RequestUserPrivacyAuthority(isSkipPrivacyWindow)
        ├── isSkipPrivacyWindow == true → 直接返回 MSERR_OK
        ├── isPrivacyAuthorityEnabled_ == true → StartAuthWindow() 弹窗
        │     → 用户 ALLOW → OnReceiveUserPrivacyAuthority(true) → OnStartScreenCapture
        │     → 用户 DENY → OnReceiveUserPrivacyAuthority(false) → 状态回 CREATED
        └── isPrivacyAuthorityEnabled_ == false → CheckScreenCapturePermission()
```

## 五、回调链路

ScreenCaptureCallBack 定义 8 个回调，通过 ScreenCaptureCallbackProxy → ScreenCaptureListenerCallback → IPC → 应用层：

```
ScreenCaptureServer 事件
  → ScreenCaptureCallbackProxy（持有 ScreenCaptureCallBack）
  → ScreenCaptureListenerCallback（桥接类，实现 ScreenCaptureCallBack）
  → ScreenCaptureListenerProxy::OnXxx()    ← IPC 发送
  → ScreenCaptureListenerStub::OnRemoteRequest() ← IPC 接收
  → ScreenCaptureCallBack::OnXxx()         ← 应用层回调
```

| 回调 | 触发时机 |
|------|---------|
| OnError | 录屏错误 |
| OnAudioBufferAvailable | 音频缓冲就绪 |
| OnVideoBufferAvailable | 视频缓冲就绪 |
| OnStateChange | 状态变化（STARTED/PAUSED/STOPPED/ENTER_PRIVATE_SCENE 等） |
| OnDisplaySelected | 显示屏选择完成 |
| OnCaptureContentChanged | 采集内容变更（HIDE/VISIBLE/UNAVAILABLE） |
| OnUserSelected | Picker 用户选择完成 |
| OnPrivacyProtect | 隐私保护状态变化 |

## 知识关联

- [[ipc-communication]] - IPC 通信与回调详解
- [[privacy-and-permission]] - 隐私保护与权限机制
- [[capture-features]] - 录制控制特性
- [[av-sync-and-buffer]] - 音视频同步与缓冲区管理
- [[design-patterns]] - 设计模式与架构解耦
- [[flows]] - 关键流程详解
- [[error-handling-and-dfx]] - 错误处理与 DFX 诊断

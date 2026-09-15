# 关键流程详解

> 录屏初始化、授权弹窗、虚拟屏幕创建、音频采集、视频缓冲、文件录制、暂停恢复、停止释放、隐私窗口、Picker、实例限制、Monitor 通知、通知栏控制等核心流程。

## 一、录屏初始化与启动流程

```
1. 创建实例
   应用 → ScreenCaptureFactory::CreateScreenCapture()
   → MediaServiceFactory → IPC → ScreenCaptureServiceStub
   → ScreenCaptureServer::Create(providers)
     → ScreenCaptureServerManager::GetNewSessionId()
     → 构造 ScreenCaptureServer（cbProxy_、InitAppInfo、instanceId、taskQue_.Start）
     → listenerManager_ 创建
     → ScreenCaptureServerManager::RegisterServer(sessionId, server, appUid)
   → 返回 ScreenCaptureClient

2. Init 配置
   → SetCaptureMode / SetDataType / InitAudioCap / InitVideoCap / SetRecorderInfo / SetOutputFile
   → 各方法校验 CAP_CONFIG，参数写入 captureConfig_
   → 状态保持 CREATED

3. StartScreenCapture(isPrivacyAuthorityEnabled)
   → 校验 CAP_INIT
   → StartScreenCaptureInner：
     → PrepareStartCapture()（注册监听 + 参数校验）
     → captureState_ → POPUP_WINDOW
     → 授权流程（见流程二）
     → OnStartScreenCapture（见流程三/四）
     → PostStartScreenCapture → captureState_ → STARTED
```

### 异常分支

```
[步骤1 异常] GetNewSessionId 失败
  → maxSessionId_ 超限 → 返回 nullptr → 应用收到 null 实例

[步骤2 异常] 参数校验失败
  → 音频采样率/通道数不支持 → MSERR_UNSUPPORT_AUD_SAMPLE_RATE / MSERR_UNSUPPORT_AUD_CHANNEL_NUM
  → 视频帧率超范围 → MSERR_INVALID_VAL
  → 状态非 CAP_CONFIG → MSERR_INVALID_OPERATION_CREATE

[步骤3 异常] PrepareStartCapture 失败
  → 通话中 → MSERR_UNSUPPORT_INCALL → 发送 STOPPED_BY_CALL 回调
  → GetDefaultDisplaySync 失败 → MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN
  → CheckAllParams 失败 → 返回对应错误码
```

## 二、授权弹窗流程

```
1. PrepareStartCapture
   → 注册 LF_ACCOUNT / LF_CALL 监听
   → CheckAllParams() 参数校验

2. CheckPrivacyWindowSkipPermission
   → VerifyAccessToken(EXEMPT_CAPTURE_SCREEN_AUTHORIZE)
   → 有权限 → isScreenCaptureAuthority_ = true

3. IsUserPrivacyAuthorityNeeded
   → appUid == ROOT_UID(0) → false（免授权）
   → 其它 → true

4. IsSkipPrivacyWindow
   → isSystemRecorder_ → true
   → CheckCustScrRecPermission && !IsPickerPopUp → true

5. RequestUserPrivacyAuthority(isSkipPrivacyWindow)
   ├── isSkipPrivacyWindow == true → 返回 MSERR_OK（跳过弹窗）
   ├── isPrivacyAuthorityEnabled_ && !isSkipPrivacyWindow
   │     → StartAuthWindow()
   │       → IsPickerPopUp() → StartPicker()
   │       → 否则 → BuildCommonParams → StartPrivacyWindow
   │         → UIExtensionAbilityConnection 弹出授权弹窗
   │     → 等待用户选择
   └── !isPrivacyAuthorityEnabled_
         → CheckScreenCapturePermission()（仅检查 CAPTURE_SCREEN 权限）

6. 用户选择 → OnReceiveUserPrivacyAuthority(isAllowed)
   ├── !isAllowed → 状态回 CREATED，回调 CANCELED
   └── isAllowed → OnStartScreenCapture → 启动采集
```

### 异常分支

```
[步骤2 异常] EXEMPT 权限未授予
  → isScreenCaptureAuthority_ = false → 进入正常授权流程

[步骤5 异常] StartPrivacyWindow 失败
  → ConnectServiceExtensionAbility 返回错误 → MSERR_UNKNOWN
  → captureState_ → STOPPED → SetErrorInfo(REQUEST_USER_PRIVACY_AUTHORITY_FAILED)

[步骤6 异常] 授权弹窗期间状态非法
  → !IsState(CAP_POPUP) → OnError → StopScreenCaptureInner
  → 用户 DENY → 状态回 CREATED，回调 CANCELED
```

## 三、虚拟屏幕创建流程

```
1. OnStartScreenCapture
   → captureState_ → STARTING
   → ORIGINAL_STREAM → StartScreenCaptureStream → StartStreamHomeVideoCapture
   → CAPTURE_FILE → StartScreenCaptureFile → CreateVirtualScreen(consumer_)

2. CreateVirtualScreen(consumer)
   → InitVirtualScreenOption(consumer) 构建 VirtualScreenOption
   → ScreenManager::CreateVirtualScreen(virScrOption) → virtualScreenId_
   → SetVirtualScreenAutoRotation
   → HandleOriginalStreamPrivacy → PrivacyProtected（设置隐私保护）
   → ShowCursorInner（光标控制）
   → PrepareVirtualScreenMirror：
     → SetScreenScaleMode（填充模式）
     → SetVirtualScreenBlackList（内容过滤黑名单）
     → MakeVirtualScreenMirror / MakeVirtualScreenExtended

3. MakeVirtualScreenMirror
   → GetDisplayIdOfWindows → 获取目标 displayId
   → ScreenManager::MakeMirror(sourceIds, mirrorIds)

4. MakeVirtualScreenExtended
   → ScreenManager::MakeVirtualScreen(virScrOption)（扩展模式）
```

### 异常分支

```
[步骤2 异常] CreateVirtualScreen 失败
  → virtualScreenId_ < 0 → MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN
  → HandleOriginalStreamPrivacy 失败 → MSERR_UNKNOWN

[步骤3 异常] MakeMirror 失败
  → DMError != DM_OK → DestroyVirtualScreen + MSERR_UNKNOWN_MAKE_MIRROR
  → GetScreenById 失败 → DestroyVirtualScreen + 上报

[屏幕连接中断] OnScreenDisconnect
  → 采集屏幕断开 → NotifyCaptureContentChanged(UNAVAILABLE)
```

## 四、音频采集启动流程

```
1. SyncAudioCaptures
   → CalcAudioCaptureSyncFlags(state) → 计算 innerStart/innerStop/micStart/micStop

2. StartInnerAudioCapture
   → 创建 AudioCapturerWrapper(innerCapInfo, cbProxy_, threadName, contentFilter)
   → innerAudioCapture_->Start(appInfo)
     → CreateAudioCapturer(appInfo)
     → BuildCapturerOptions → 设置采样率/通道/源类型
     → SetupCapturerCallbacks → AudioCapturerCallbackImpl
     → AudioCapturer::Start
   → audioSource_->SetCapture(ALL_PLAYBACK, innerAudioCapture_)

3. StartMicAudioCapture
   → 创建 AudioCapturerWrapper(micCapInfo, cbProxy_, threadName, emptyFilter)
   → micAudioCapture_->SetIsInVoIPCall(isVoip)
   → micAudioCapture_->Start(appInfo)
   → audioSource_->SetCapture(MIC, micAudioCapture_)

4. AudioCapturer 数据回调
   → AudioCapturerReadCallbackImpl::OnReadData(length)
   → AudioCapturerWrapper::OnReadData(length)
   → CreateCacheBuffer → CacheBuffer 入队 availBuffers_
   → NotifyBufferAvailable → AudioDataSource::OnBufferAvailable(type)
```

### 异常分支

```
[步骤2 异常] InnerAudioCapture 创建失败
  → AudioCapturer::Start 返回错误 → 返回错误码
  → 不影响视频采集继续

[步骤3 异常] MicAudioCapture 启动失败
  → 返回错误码 → cbProxy_->OnStateChange(MIC_UNAVAILABLE)
  → ignoreMicError=true 时不阻断流程

[通话中断] 通话期间
  → micStop=true → micAudioCapture_->Stop()
  → OnStateChange(MIC_UNAVAILABLE)
```

## 五、视频缓冲获取流程

```
1. 虚拟屏幕渲染帧
   → Surface Producer 写入 SurfaceBuffer
   → Consumer (ScreenCapBufferConsumerListener) 收到 OnBufferAvailable

2. OnBufferAvailable
   → 消息队列 push GET_BUFFER
   → bufferAvailableWorkerCv_.notify_one()

3. SurfaceBufferThreadRun（独立线程）
   → 取出 GET_BUFFER 消息
   → 消息队列超 MAX_MESSAGE_QUEUE_SIZE(5) → 丢弃旧消息
   → OnBufferAvailableAction

4. OnBufferAvailableAction
   → consumer_->AcquireBuffer(buffer, fence, timestamp, damage)
   → acquireFence->Wait(1000ms) → flushFence
   → buffer->InvalidateCache()（MMZ 缓存失效）
   → availBuffers_.size() > MAX_BUFFER_SIZE(3) → 丢帧
   → availBuffers_.push(SurfaceBufferEntry)
   → ProcessVideoBufferCallBack → OnVideoBufferAvailable(true)

5. 应用 AcquireVideoBuffer
   → bufferCond_.wait_for(1000ms) 等待 availBuffers_ 非空
   → 返回 availBuffers_.front()

6. 应用 ReleaseVideoBuffer
   → consumer_->ReleaseBuffer(buffer, -1)
   → availBuffers_.pop()
```

### 异常分支

```
[步骤4 异常] AcquireBuffer 失败
  → GSERROR_OK != acquireBufferRet → 记录日志，丢弃当前帧

[步骤4 异常] 缓冲队列满
  → availBuffers_.size() > 3 → ReleaseBuffer(-1) 丢弃帧 → 日志 "consume slow, drop video frame"

[步骤5 异常] AcquireVideoBuffer 超时
  → wait_for 超过 1000ms → 返回 MSERR_UNKNOWN

[线程异常] Buffer 线程未启动
  → surfaceCb_ == nullptr → AcquireVideoBuffer 返回 MSERR_NO_MEMORY
```

## 六、文件录制流程

```
1. StartScreenCaptureFile（CAPTURE_FILE 模式）
   → InitRecorder()
     → providers_->CreateRecorder() → recorder_
     → 配置音频编码/视频编码/输出格式/输出文件
     → audioSource_ 创建（AudioDataSourceGeneric，MIX_ALL 策略）

2. SyncAudioCaptures
   → 启动 innerAudioCapture_ / micAudioCapture_
   → audioSource_->SetCapture(ALL_PLAYBACK/MIC, capture)

3. recorder_->Start()

4. CreateVirtualScreen(consumer_)
   → 虚拟屏幕提供视频帧 → Recorder 通过 Surface 获取视频

5. AudioDataSource::ReadAt
   → Recorder 请求数据 → 根据混音模式选择数据源
   → A/V 同步对齐 → 混音/透传 → 写入 AVBuffer
```

### 异常分支

```
[步骤1 异常] InitRecorder 失败
  → CreateRecorder 返回 null → MSERR_UNKNOWN_CREAT_RECORDER
  → ON_SCOPE_EXIT → StopAudioCapture

[步骤3 异常] Recorder 启动失败
  → recorder_->Start 返回错误 → ON_SCOPE_EXIT → recorder_->Release

[步骤5 异常] AudioDataSource 无数据
  → 麦克风/内录均无数据 → SKIP_WITHOUT_LOG
  → A/V 同步失败 → 填充静音帧
```

## 七、暂停 / 恢复流程

```
暂停：
1. PauseScreenCaptureInner(PAUSED_BY_APP)
   → 校验 CAP_RUNNING + enablePause
   → FILE 模式 → PauseRecorder → recorder_->Pause()
   → PauseVideoCapture：
     ├── CAPTURE_VIRTUAL_EXTENDED_SCREEN → DestroyVirtualScreen
     └── 其它 → StopMirror（停止镜像但保留虚拟屏幕）
   → StopAudioCapture → micAudioCapture_/innerAudioCapture_ Stop
   → audioSource_->Pause()
   → isTimePaused_ = true
   → captureState_ → PAUSED
   → 更新通知栏（PAUSE → RESUME 按钮）
   → OnStateChange(PAUSED_BY_APP)

恢复：
1. ResumeScreenCaptureInner(RESUMED_BY_APP)
   → 校验 CAP_PAUSED + enablePause
   → 通话期间 → StopScreenCaptureByEvent(STOPPED_BY_CALL) + Release
   → ResumeVideoCapture：
     ├── CAPTURE_VIRTUAL_EXTENDED_SCREEN → CreateVirtualScreen
     └── 其它 → MakeVirtualScreenMirror
   → SyncAudioCaptures(true)
   → audioSource_->Resume()
   → FILE 模式 → ResumeRecorder → recorder_->Resume()
   → isTimePaused_ = false
   → captureState_ → RESUMED
   → 更新通知栏（RESUME → PAUSE 按钮）
   → OnStateChange(RESUMED_BY_APP)
```

### 异常分支

```
[暂停异常] PauseRecorder 失败
  → StopCaptureOnError("pauseRecording fail") → OnError + StopScreenCaptureInner

[暂停异常] PauseVideoCapture 失败
  → StopCaptureOnError → 停止录屏并上报

[恢复异常] ResumeVideoCapture 失败
  → StopCaptureOnError("resumeRecording fail")

[恢复异常] SyncAudioCaptures 失败
  → StopCaptureOnError → 停止录屏并上报

[恢复时通话] 通话中且未保持
  → StopScreenCaptureByEvent(STOPPED_BY_CALL) + Release
```

## 八、停止与释放流程

```
停止：
1. StopScreenCapture
   → StopScreenCaptureByEvent(INVALID)
   → StopScreenCaptureInner(stateCode)：
     → cbProxy_->SetBufferActive(false)
     → !CAP_ACTIVE → StopNotStartedScreenCapture（未启动就停止）
     ├── CAPTURE_FILE → StopScreenCaptureRecorder
     │   → audioSource_->Stop + recorder_->Stop(false)
     │   → DestroyVirtualScreen + recorder_->Release + StopAudioCapture
     └── ORIGINAL_STREAM → StopAudioAndVideoCapture
         → StopAudioCapture + StopVideoCapture
     → PostStopScreenCapture(stateCode)：
       → Monitor.CallOnScreenCaptureFinished(pid)
       → OnStateChange(stateCode)
       → CancelNotification
       → LastPidUpdatePrivacyUsingPermissionState(STOP_VIDEO)
       → captureState_ → STOPPED
     → listenerManager_->UnregisterListeners()

释放：
2. Release → ReleaseInner
   → 若 CAP_ALIVE → StopScreenCaptureInner(INVALID)
   → RemoveSaAppInfoMap + sessionId_ = -1
   → SetMetaDataReport → HiSysEvent 上报
   → RemoveScreenCaptureServerMap(sessionId)
   → taskQue_.Stop + CloseFd
   → g_serverMap.erase → 析构
```

### 异常分支

```
[停止异常] StopScreenCaptureByEvent 重复调用
  → !IsState(CAP_ALIVE) → 返回 MSERR_OK（幂等）

[停止异常] Recorder Stop 失败
  → MSERR_UNKNOWN_RECORDER_STOP → 继续清理资源

[停止异常] 虚拟屏幕销毁失败
  → virtualScreenId_ == SCREEN_ID_INVALID → 跳过

[释放异常] 未先停止就 Release
  → ReleaseInner 检测 CAP_ALIVE → 自动 StopScreenCaptureInner
```

## 九、隐私窗口处理流程

```
1. 系统检测隐私窗口变化
   → PrivateWindowListenerWrapper::OnPrivateWindow(hasPrivate)

2. ScreenCaptureServer::OnPrivateWindowChange(hasPrivate)
   → taskQue_ 异步入队
   → cbProxy_->OnStateChange(ENTER_PRIVATE_SCENE / EXIT_PRIVATE_SCENE)
   → 应用层收到通知

3. 应用响应
   ├── ENTER_PRIVATE_SCENE → 应用可选择停止录屏或继续
   └── EXIT_PRIVATE_SCENE → 恢复正常录屏

4. 隐私保护开关变化
   → NotifyprivacyProtect()
   → OnPrivacyProtect({appPrivacyProtection, systemPrivacyProtection})
```

### 异常分支

```
[步骤2 异常] 实例已停止
  → taskQue_ 已 Stop → 任务不执行

[步骤4 异常] cbProxy_ 为空
  → 回调被忽略
```

## 十、Picker 用户选择流程

```
1. PresentPicker
   → 校验 CAP_RUNNING
   → isPresentPickerPopWindow_ = true
   → StartPicker（SUPPORT_SCREEN_CAPTURE_PICKER）
     → 弹出系统 Picker UI

2. 用户选择窗口/屏幕/应用
   → ReportAVScreenCaptureUserChoice(content) → Controller IPC
   → ScreenCaptureServer::ReportAVScreenCaptureUserChoiceImpl(content)
   → HandlePresentPickerWindowCase(root, content)：
     → isPresentPickerPopWindow_ = false
     → 用户未允许 → DestroyVirtualScreen + Stop
     → DestroyVirtualScreen（销毁旧虚拟屏幕）
     → SetCaptureConfig(captureMode, missionId)（更新配置）
     → OnReceiveUserPrivacyAuthority(true) → OnStartScreenCapture

3. 用户选择信息回调
   → FinishPrepareSelectWindow
   → cbProxy_->OnUserSelected(selectionInfo)
```

### 异常分支

```
[步骤1 异常] 非 CAP_RUNNING 状态
  → MSERR_INVALID_OPERATION

[步骤1 异常] Picker 不支持
  → MSERR_UNKNOWN_UNSUPPORT（条件编译关闭）

[步骤2 异常] 用户取消选择
  → DestroyVirtualScreen → 停止录屏

[步骤2 异常] 新配置参数无效
  → SetCaptureConfig 失败 → 回退配置
```

## 十一、实例数量限制流程

```
1. ScreenCaptureServerManager::CanScreenCaptureInstanceBeCreate(appUid)
   → 检查 maxAppLimit_(4) → 全局实例数
   → 检查 maxSessionPerUid_(4) → 同一 UID 实例数
   → 检查 maxSCServerDataTypePerUid_(2) → 同一 UID 同一 DataType 实例数

2. SetAndCheckLimit
   → CanScreenCaptureInstanceBeCreate(IPCSkeleton::GetCallingUid())
   → 失败 → MSERR_INVALID_OPERATION

3. SetAndCheckSaLimit（SA 调用）
   → IsSAUidValid(saUid, appUid) → SA-UID 映射校验
   → CanScreenCaptureInstanceBeCreate(appUid)
   → AddSaAppInfoMap(saUid, appUid)
```

### 异常分支

```
[步骤1 异常] 全局实例超限
  → 超过 4 → MSERR_INVALID_OPERATION

[步骤1 异常] 同 UID 超限
  → 超过 4 → MSERR_INVALID_OPERATION

[步骤3 异常] SA-UID 已存在
  → IsSAUidValid 失败 → MSERR_INVALID_OPERATION
```

## 十二、Monitor 通知流程

```
1. 录屏启动成功
   → PostStartScreenCaptureSuccessAction
   → providers_->GetScreenCaptureMonitor().CallOnScreenCaptureStarted(appPid)
   → MonitorServer 遍历所有监听器
   → ScreenCaptureMonitorListenerProxy::OnScreenCaptureStarted(pid) (IPC)
   → 应用层 ScreenCaptureMonitorListener::OnScreenCaptureStarted(pid)

2. 录屏停止
   → PostStopScreenCapture
   → providers_->GetScreenCaptureMonitor().CallOnScreenCaptureFinished(appPid)
   → MonitorServer 遍历所有监听器
   → 应用层 OnScreenCaptureFinished(pid)

3. 录屏服务死亡
   → MonitorServer DeathRecipient → OnScreenCaptureDied
```

## 十三、通知栏控制流程

```
1. 创建通知
   → StartNotification
   → NotificationHelper::SubscribeLocalLiveViewNotification(NOTIFICATION_SUBSCRIBER)
   → InitLiveViewContent（初始化通知内容：标题/子标题/按钮）
   → SetupPublishRequest（设置不可移除/实时进行中/WantAgent）
   → NotificationHelper::PublishNotification(request)

2. 胶囊按钮响应
   → NotificationSubscriber::OnResponse(notificationId, buttonOption)
   → 通过 notificationId 找到 ScreenCaptureServer
   → server->HandleNotificationButtonResponse(buttonName)
     ├── "stop" → StopScreenCaptureByEvent(STOPPED_BY_USER)
     ├── "pause" → PauseScreenCaptureInner(PAUSED_BY_USER)
     ├── "resume" → ResumeScreenCaptureInner(RESUMED_BY_USER)
     └── "mic" → UpdateMicrophoneEnabled

3. 更新通知
   → UpdateLiveViewContent → 更新通知内容
   → SetupPublishRequest → NotificationHelper::PublishNotification

4. 移除通知
   → NotificationHelper::CancelNotification(notificationId)
```

### 异常分支

```
[步骤1 异常] 通知发布失败
  → TryNotificationOnPostStartScreenCapture == MSERR_UNKNOWN → 停止录屏

[步骤2 异常] 服务器实例不存在
  → GetScreenCaptureServerById 返回 null → 忽略按钮响应

[步骤3 异常] 语言切换
  → OnLanguageSwitch → UpdateLiveViewContent → 刷新通知文本
```

## 知识关联

- [[capture-lifecycle]] - 录屏完整生命周期
- [[ipc-communication]] - IPC 通信与回调机制
- [[privacy-and-permission]] - 隐私保护与权限机制
- [[av-sync-and-buffer]] - 音视频同步与缓冲区管理
- [[error-handling-and-dfx]] - 错误处理与 DFX 诊断

# 错误处理与 DFX 诊断

> 错误码体系、错误处理策略、DFX 诊断框架、通知栏实时视图、常见错误场景。

## 一、错误码体系

### 1.1 C API 层（OH_AVSCREEN_CAPTURE_ErrCode）

| 错误码 | 值 | 说明 |
|--------|-----|------|
| AV_SCREEN_CAPTURE_ERR_OK | 0 | 操作成功 |
| AV_SCREEN_CAPTURE_ERR_NO_MEMORY | 1 | 内存不足 |
| AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT | 2 | 操作不允许 |
| AV_SCREEN_CAPTURE_ERR_INVALID_VAL | 3 | 参数无效 |
| AV_SCREEN_CAPTURE_ERR_IO | 4 | IO 错误 |
| AV_SCREEN_CAPTURE_ERR_TIMEOUT | 5 | 超时 |
| AV_SCREEN_CAPTURE_ERR_UNKNOWN | 6 | 未知错误 |
| AV_SCREEN_CAPTURE_ERR_SERVICE_DIED | 7 | 服务死亡 |
| AV_SCREEN_CAPTURE_ERR_INVALID_STATE | 8 | 状态不支持 |
| AV_SCREEN_CAPTURE_ERR_UNSUPPORT | 9 | 接口不支持 |
| AV_SCREEN_CAPTURE_ERR_EXTEND_START | 100 | 扩展错误起始 |

### 1.2 内部层（MediaServiceErrCode）

| 错误码 | 说明 |
|--------|------|
| MSERR_OK | 操作成功 |
| MSERR_INVALID_OPERATION_CREATE | 非法创建/配置操作（非 CREATED 态） |
| MSERR_INVALID_OPERATION | 非法状态操作 |
| MSERR_INVALID_OPERATION_STARTED_RESUMED | 非 STARTED/RESUMED 态操作 |
| MSERR_INVALID_OPERATION_PAUSED | 非 PAUSED 态操作 |
| MSERR_INVALID_OPERATION_ENABLEPAUSE | 未启用 enablePause |
| MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN | 虚拟屏幕创建失败 |
| MSERR_UNKNOWN_MAKE_MIRROR | 镜像创建失败 |
| MSERR_INVALID_VAL | 参数无效 |
| MSERR_UNSUPPORT | 不支持 |
| MSERR_UNSUPPORT_INCALL | 通话中不支持 |
| MSERR_UNKNOWN_INCALL | 通话中未知错误 |
| MSERR_UNKNOWN_RECORDER_STOP | Recorder 停止失败 |
| MSERR_UNKNOWN_RECORDER_PAUSE | Recorder 暂停失败 |
| MSERR_UNKNOWN_RECORDER_RESUME | Recorder 恢复失败 |
| MSERR_UNKNOWN_CREAT_RECORDER | Recorder 创建失败 |
| MSERR_UNKNOWN_UNSUPPORT | 不支持（编译宏关闭） |
| MSERR_INVALID_OPERATION_UNSUPPORT | 不支持（平台/版本） |
| MSERR_NO_MEMORY | 内存不足 |
| MSERR_STOP_FAILED | 停止失败 |
| MSERR_UNKNOWN | 未知错误 |

## 二、错误处理策略

| 策略 | 说明 |
|------|------|
| 统一返回值 | 所有方法返回 `int32_t` 错误码，`MSERR_OK(0)` 为成功 |
| 状态机能力位图校验 | `IsState(cap)` 通过能力位图检查当前状态是否允许操作 |
| 参数校验 | `CHECK_AND_RETURN_RET_LOG` 宏统一参数/状态校验 |
| 错误传播链 | ScreenCaptureServer → ScreenCaptureListenerCallback → IPC → 应用层 |
| ON_SCOPE_EXIT 守卫 | 关键流程使用作用域守卫确保异常时资源释放 |
| StopCaptureOnError | 暂停/恢复等操作失败时调用 `StopCaptureOnError` 停止录屏并上报错误 |

### 错误传播链

```
ScreenCaptureServer 错误
  → cbProxy_->OnError(errorType, errorCode)  (ScreenCaptureCallbackProxy)
  → ScreenCaptureListenerCallback::OnError()
  → ScreenCaptureListenerProxy::OnError()    (IPC 发送)
  → ScreenCaptureListenerStub::OnRemoteRequest()
  → ScreenCaptureCallBack::OnError()         (应用层回调)
```

## 三、DFX 诊断

### 3.1 StatisticalEventInfo 统计打点

```cpp
struct StatisticalEventInfo {
    int32_t errCode = 0;
    std::string errMsg;
    int32_t captureDuration = -1;   // 录制时长（ms）
    bool userAgree = false;         // 用户是否同意授权
    bool requireMic = false;        // 是否需要麦克风
    bool enableMic = false;         // 麦克风是否开启
    std::string videoResolution;    // 视频分辨率
    StopReason stopReason;          // 停止原因
    int32_t startLatency = -1;      // 启动延迟（ms）
};
```

### 3.2 SetMetaDataReport → HiSysEvent 上报

Release 时通过 `SetMetaDataReport()` 将统计信息通过 `Media::Meta` 上报：

| Meta Tag | 字段 |
|-----------|------|
| SCREEN_CAPTURE_ERR_CODE | errCode |
| SCREEN_CAPTURE_ERR_MSG | errMsg |
| SCREEN_CAPTURE_DURATION | captureDuration |
| SCREEN_CAPTURE_AV_TYPE | avType_ |
| SCREEN_CAPTURE_DATA_TYPE | dataMode_ |
| SCREEN_CAPTURE_USER_AGREE | userAgree |
| SCREEN_CAPTURE_REQURE_MIC | requireMic |
| SCREEN_CAPTURE_ENABLE_MIC | enableMic |
| SCREEN_CAPTURE_VIDEO_RESOLUTION | videoResolution |
| SCREEN_CAPTURE_STOP_REASON | stopReason |
| SCREEN_CAPTURE_START_LATENCY | startLatency |

### 3.3 SetMediaKitReport → MediaKit 上报

录屏开始/失败时调用，上报详细配置信息：

```json
{
  "captureMode": 0,
  "dataType": "0",
  "videoCapDisplayId": 0,
  "videoFrameWidth": 1920,
  "videoFrameHeight": 1080,
  "videoSourceType": 1,
  "micAudioSampleRate": 48000,
  "innerAudioSource": 2,
  "enableDeviceLevelCapture": false,
  "keepCaptureDuringCall": false,
  "pickerPopUp": -1,
  "fillMode": 0,
  "enablePause": false
  ...
}
```

通过 `MediaEvent::MediaKitStatistics` 上报。

### 3.4 StopReason 枚举

| 枚举值 | 值 | 说明 |
|--------|-----|------|
| NORMAL_STOPPED | 0 | 正常停止 |
| RECEIVE_USER_PRIVACY_AUTHORITY_FAILED | 1 | 接收用户授权失败 |
| POST_START_SCREENCAPTURE_HANDLE_FAILURE | 2 | 启动后处理失败 |
| REQUEST_USER_PRIVACY_AUTHORITY_FAILED | 3 | 请求用户授权失败 |
| STOP_REASON_INVALID | 4 | 无效停止原因 |

### 3.5 FaultEvent 故障上报

```cpp
FaultScreenCaptureEventWrite(appName, instanceId, avType, dataMode_, errCode, errMsg);
```

关键故障路径调用，通过 HiSysEvent FAULT 类型上报。

## 四、通知栏实时视图

### 4.1 NotificationLocalLiveViewContent

录屏期间显示实时通知栏，包含胶囊按钮和计时器。

| 组件 | 说明 |
|------|------|
| `localLiveViewContent_` | 通知栏内容对象 |
| `notificationId_` | = sessionId_，用于通知栏标识 |
| `SetupPublishRequest` | 配置通知请求（不可移除、实时进行中） |

### 4.2 胶囊按钮

| 按钮名称 | 动作 | 对应方法 |
|----------|------|---------|
| STOP | 停止录屏 | `StopScreenCaptureByEvent(STOPPED_BY_USER)` |
| PAUSE | 暂停录屏 | `PauseScreenCaptureInner(PAUSED_BY_USER)` |
| RESUME | 恢复录屏 | `ResumeScreenCaptureInner(RESUMED_BY_USER)` |
| MIC | 麦克风开关 | `UpdateMicrophoneEnabled()` |

### 4.3 计时器

通过 `startTime_` 和 `isTimePaused_` 管理计时：
- 开始：`startTime_ = GetCurrentMillisecond()`
- 暂停：`isTimePaused_ = true`
- 恢复：`isTimePaused_ = false`
- 停止：`captureDuration = endTime - startTime - startLatency`

### 4.4 HandleNotificationButtonResponse

```cpp
void HandleNotificationButtonResponse(const std::string &buttonName) {
    if (buttonName == "stop") → StopScreenCaptureByEvent
    else if (buttonName == "pause") → PauseScreenCaptureInner
    else if (buttonName == "resume") → ResumeScreenCaptureInner
    else if (buttonName == "mic") → UpdateMicrophoneEnabled
}
```

### 4.5 NotificationSubscriber

```cpp
class NotificationSubscriber : public NotificationLocalLiveViewSubscriber {
    void OnConnected() override;
    void OnDisconnected() override;
    void OnResponse(notificationId, buttonOption) override;  // 按钮响应
    void OnDied() override;
};
```

通过 `notificationId_` 定位对应的 `ScreenCaptureServer` 实例。

### 4.6 通知栏更新时机

| 事件 | 更新内容 |
|------|---------|
| 暂停 | 按钮从 PAUSE 切换为 RESUME，计时暂停 |
| 恢复 | 按钮从 RESUME 切换为 PAUSE，计时恢复 |
| 语言切换 | `UpdateLiveViewContent` 刷新通知文本 |
| 停止 | `CancelNotification` 移除通知 |

## 五、常见错误场景与处理表

| 场景 | 原因 | 错误码 | 处理方式 |
|------|------|--------|---------|
| 非法状态启动 | 非 CREATED/STOPPED | MSERR_INVALID_OPERATION | 校验 `CAP_INIT` |
| 配置在运行中 | 非 CREATED | MSERR_INVALID_OPERATION_CREATE | 校验 `CAP_CONFIG` |
| 暂停在非运行态 | 非 STARTED/RESUMED | MSERR_INVALID_OPERATION_STARTED_RESUMED | 校验 `CAP_RUNNING` |
| 恢复在非暂停态 | 非 PAUSED | MSERR_INVALID_OPERATION_PAUSED | 校验 `CAP_PAUSED` |
| 未启用 enablePause | strategy.enablePause=false | MSERR_INVALID_OPERATION_ENABLEPAUSE | 前置条件校验 |
| 虚拟屏幕创建失败 | DisplayManager 返回错误 | MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN | 停止录屏并上报 |
| 镜像创建失败 | MakeMirror 返回错误 | MSERR_UNKNOWN_MAKE_MIRROR | DestroyVirtualScreen + 上报 |
| 通话中启动 | InCallObserver 检测通话 | MSERR_UNSUPPORT_INCALL | 发送 STOPPED_BY_CALL 回调 |
| 麦克风启动失败 | AudioCapturer 创建失败 | MSERR_UNKNOWN | 发送 MIC_UNAVAILABLE 回调 |
| 实例数超限 | 超过 maxAppLimit/maxSessionPerUid | MSERR_INVALID_OPERATION | CanScreenCaptureInstanceBeCreate |
| Recorder 停止失败 | recorder_->Stop 返回错误 | MSERR_UNKNOWN_RECORDER_STOP | 继续清理资源 |
| 用户拒绝授权 | OnReceiveUserPrivacyAuthority(false) | MSERR_UNKNOWN | 状态回退 CREATED，回调 CANCELED |
| Picker 不支持 | 编译宏未开启 | MSERR_UNKNOWN_UNSUPPORT | 条件编译返回 |

## 知识关联

- [[capture-lifecycle]] - 录屏完整生命周期
- [[ipc-communication]] - IPC 通信与回调机制
- [[privacy-and-permission]] - 隐私保护与权限机制
- [[flows]] - 关键流程详解（通知栏控制流程）

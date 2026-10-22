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
| 统一返回值 | 所有方法返回 int32_t 错误码，MSERR_OK(0) 为成功 |
| 状态机能力位图校验 | IsState(cap) 通过能力位图检查当前状态是否允许操作 |
| 参数校验 | CHECK_AND_RETURN_RET_LOG 宏统一参数/状态校验 |
| 错误传播链 | Server → ListenerCallback → IPC → 应用层 |
| ON_SCOPE_EXIT 守卫 | 关键流程使用作用域守卫确保异常时资源释放 |
| StopCaptureOnError | 暂停/恢复等操作失败时停止录屏并上报错误 |

### 错误传播链

Server 错误 → 回调代理 OnError → 桥接类 → ListenerProxy(IPC 发送) → ListenerStub(IPC 接收) → 应用层 OnError 回调。

## 三、DFX 诊断

### 3.1 StatisticalEventInfo 统计打点

录屏统计打点信息结构体：

| 字段 | 说明 |
|------|------|
| errCode / errMsg | 错误码与错误信息 |
| captureDuration | 录制时长（ms） |
| userAgree | 用户是否同意授权 |
| requireMic / enableMic | 是否需要麦克风 / 麦克风是否开启 |
| videoResolution | 视频分辨率 |
| stopReason | 停止原因 |
| startLatency | 启动延迟（ms） |

### 3.2 SetMetaDataReport → HiSysEvent 上报

Release 时将统计信息通过 Meta 上报：

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

录屏开始/失败时调用，上报详细配置信息（captureMode/dataType/视频分辨率/采样率/策略等），通过 MediaEvent::MediaKitStatistics 上报。

### 3.4 StopReason 枚举

| 枚举值 | 值 | 说明 |
|--------|-----|------|
| NORMAL_STOPPED | 0 | 正常停止 |
| RECEIVE_USER_PRIVACY_AUTHORITY_FAILED | 1 | 接收用户授权失败 |
| POST_START_SCREENCAPTURE_HANDLE_FAILURE | 2 | 启动后处理失败 |
| REQUEST_USER_PRIVACY_AUTHORITY_FAILED | 3 | 请求用户授权失败 |
| STOP_REASON_INVALID | 4 | 无效停止原因 |

### 3.5 FaultEvent 故障上报

关键故障路径调用 FaultScreenCaptureEventWrite，通过 HiSysEvent FAULT 类型上报。

## 四、通知栏实时视图

### 4.1 NotificationLocalLiveViewContent

录屏期间显示实时通知栏，包含胶囊按钮和计时器。notificationId 与 sessionId 一致，用于通知栏标识。

### 4.2 胶囊按钮

| 按钮名称 | 动作 |
|----------|------|
| STOP | 停止录屏（STOPPED_BY_USER） |
| PAUSE | 暂停录屏（PAUSED_BY_USER） |
| RESUME | 恢复录屏（RESUMED_BY_USER） |
| MIC | 麦克风开关 |

### 4.3 计时器

通过 startTime 和 isTimePaused 管理：开始记录起始时间；暂停置位；恢复清位；停止计算 captureDuration = endTime - startTime - startLatency。

### 4.4 通知栏更新时机

| 事件 | 更新内容 |
|------|---------|
| 暂停 | 按钮从 PAUSE 切换为 RESUME，计时暂停 |
| 恢复 | 按钮从 RESUME 切换为 PAUSE，计时恢复 |
| 语言切换 | 刷新通知文本 |
| 停止 | CancelNotification 移除通知 |

## 五、常见错误场景与处理表

| 场景 | 原因 | 错误码 | 处理方式 |
|------|------|--------|---------|
| 非法状态启动 | 非 CREATED/STOPPED | MSERR_INVALID_OPERATION | 校验 INIT |
| 配置在运行中 | 非 CREATED | MSERR_INVALID_OPERATION_CREATE | 校验 CONFIG |
| 暂停在非运行态 | 非 STARTED/RESUMED | MSERR_INVALID_OPERATION_STARTED_RESUMED | 校验 RUNNING |
| 恢复在非暂停态 | 非 PAUSED | MSERR_INVALID_OPERATION_PAUSED | 校验 PAUSED |
| 未启用 enablePause | strategy.enablePause=false | MSERR_INVALID_OPERATION_ENABLEPAUSE | 前置条件校验 |
| 虚拟屏幕创建失败 | DisplayManager 返回错误 | MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN | 停止录屏并上报 |
| 镜像创建失败 | MakeMirror 返回错误 | MSERR_UNKNOWN_MAKE_MIRROR | 销毁虚拟屏幕 + 上报 |
| 通话中启动 | 通话检测 | MSERR_UNSUPPORT_INCALL | 发送 STOPPED_BY_CALL 回调 |
| 麦克风启动失败 | AudioCapturer 创建失败 | MSERR_UNKNOWN | 发送 MIC_UNAVAILABLE 回调 |
| 实例数超限 | 超全局/单 UID 上限 | MSERR_INVALID_OPERATION | 创建前检查计数 |
| Recorder 停止失败 | recorder Stop 返回错误 | MSERR_UNKNOWN_RECORDER_STOP | 继续清理资源 |
| 用户拒绝授权 | 用户 DENY | MSERR_UNKNOWN | 状态回退 CREATED，回调 CANCELED |
| Picker 不支持 | 编译宏未开启 | MSERR_UNKNOWN_UNSUPPORT | 条件编译返回 |

## 知识关联

- [capture-lifecycle](capture-lifecycle.md) - 录屏完整生命周期
- [ipc-communication](ipc-communication.md) - IPC 通信与回调机制
- [privacy-and-permission](privacy-and-permission.md) - 隐私保护与权限机制
- [flows](flows.md) - 关键流程详解（通知栏控制流程）

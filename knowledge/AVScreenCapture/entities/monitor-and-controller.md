# Monitor 与 Controller 实体

> ScreenCaptureMonitor（全局监控）与 ScreenCaptureController（用户选择控制）实体

## 实体概念

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| ScreenCaptureMonitorServer | Monitor 服务端单例，实现 IInnerScreenCaptureMonitorService | runningCapturePidCounts_ (map\<pid,count\>) 运行中 PID 计数；screenCaptureMonitorCbSet_ (set\<listener\>) 监听器集合；systemScreenRecorderPid_ 系统录制器 PID；CallOnScreenCaptureStarted/Finished 通知监听器；AddRunningCapturePid/RemoveRunningCapturePid 管理 PID | 全局单例 |
| ScreenCaptureMonitorClient | Monitor 客户端，持有 IPC 代理 + 回调存根 | screenCaptureMonitorProxy_ (IStandardScreenCaptureMonitorService)；listenerStub_ (ScreenCaptureMonitorListenerStub)；screenCaptureMonitorClientCallbacks_ 回调集合；CreateListenerObject/CloseListenerObject 管理 IPC 回调通路 | 客户端 |
| ScreenCaptureMonitorListener | 监听器基类（RefBase） | OnScreenCaptureStarted(pid) 录制开始；OnScreenCaptureFinished(pid) 录制结束；OnScreenCaptureDied() 录制进程死亡 | 监听器基类 |
| ScreenCaptureControllerServer | 用户选择处理服务端，实现 IScreenCaptureController | ReportAVScreenCaptureUserChoice(sessionId, choice) JSON 解析分发；GetAVScreenCaptureConfigurableParameters(sessionId, resultStr) 获取可配置参数 | 服务端类 |
| ScreenCaptureControllerClient | Controller 客户端 | screenCaptureControllerProxy_ (IStandardScreenCaptureController)；ReportAVScreenCaptureUserChoice/GetAVScreenCaptureConfigurableParameters 透传；MediaServerDied 死亡通知 | 客户端 |
| ScreenCaptureMonitorCallback | Monitor NAPI 回调适配 | OnScreenCaptureStarted/OnScreenCaptureFinished/OnScreenCaptureDied 桥接；uv_async 投递 JS 线程；refMap_ 管理回调引用 | NAPI 回调适配 |
| ScreenCaptureMonitorNapi | Monitor NAPI 桥接 | JsGetScreenCaptureMonitor 获取实例；JsSetEventCallback/JsCancelEventCallback 事件注册；JsIsSystemScreenRecorderWorking 属性查询 | NAPI 桥接类 |

## 上下文与场景

### 交互流程

**Monitor 监听流程（ScreenCaptureServer → MonitorServer → 通知监听器）**：

```
ScreenCaptureServer::StartScreenCapture
  → IInnerScreenCaptureMonitorService::CallOnScreenCaptureStarted(pid)
  → ScreenCaptureMonitorServer::CallOnScreenCaptureStarted
    → AddRunningCapturePid(pid)  // PID 计数 +1
    → 遍历 screenCaptureMonitorCbSet_
      → ScreenCaptureMonitorListenerProxy (序列化)
      → IPC Binder
      → ScreenCaptureMonitorListenerStub (反序列化)
      → 应用层 ScreenCaptureMonitorListener::OnScreenCaptureStarted(pid)

ScreenCaptureServer::StopScreenCapture
  → IInnerScreenCaptureMonitorService::CallOnScreenCaptureFinished(pid)
  → ScreenCaptureMonitorServer::CallOnScreenCaptureFinished
    → RemoveRunningCapturePid(pid)  // PID 计数 -1
    → 通知监听器 OnScreenCaptureFinished(pid)
```

**Monitor 查询流程**：

```
应用 → ScreenCaptureMonitorNapi::JsIsSystemScreenRecorderWorking
  → ScreenCaptureMonitorImpl::IsSystemScreenRecorderWorking
  → ScreenCaptureMonitorClient → IPC
  → ScreenCaptureMonitorServiceStub
  → ScreenCaptureMonitorServer::IsSystemScreenRecorderWorking
  → 返回 bool
```

**Controller 用户选择流程（Picker → Controller → ScreenCaptureServer）**：

```
系统 Picker UI
  → 应用 AVScreenCaptureNapi::JsReportAVScreenCaptureUserChoice
  → ScreenCaptureControllerImpl::ReportAVScreenCaptureUserChoice
  → ScreenCaptureControllerClient → IPC
  → ScreenCaptureControllerStub
  → ScreenCaptureControllerServer::ReportAVScreenCaptureUserChoice
    → JSON 解析 (choice)
    → HandlePopupWindowCase / HandleStreamDataCase / HandlePresentPickerWindowCase
    → ScreenCaptureServer::ReportAVScreenCaptureUserChoice(content)
    → PrepareSelectWindow / FinishPrepareSelectWindow
```

### 使用场景

| 实体 | 适用场景 |
|------|---------|
| ScreenCaptureMonitorServer | 全局监控所有屏幕录制实例的开始/结束/死亡 |
| ScreenCaptureMonitorClient | 应用进程通过 IPC 查询录制状态、注册监听 |
| ScreenCaptureControllerServer | 处理系统 Picker 用户选择结果，分发到对应 ScreenCaptureServer |
| ScreenCaptureControllerClient | 应用进程上报用户选择、获取可配置参数 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 单例约束 | ScreenCaptureMonitorServer 是进程级单例，GetInstance() 获取 |
| 线程安全 | ScreenCaptureMonitorServer 使用 mutex_ 保护 runningCapturePidCounts_ 和 screenCaptureMonitorCbSet_ |
| 业务规则 | PID 计数为引用计数，同一 PID 多个录制实例时计数累加，计数归零才通知 Finished |
| 业务规则 | systemScreenRecorderPid_ 由 SetSystemScreenRecorderPid 设置，IsSystemScreenRecorder 判断是否系统录制器 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上游依赖 | [[api-layer]] — ScreenCaptureMonitor/ScreenCaptureController InnerAPI 接口 |
| 下游影响 | [[service-layer]] — ScreenCaptureServer 通过 IInnerScreenCaptureMonitorService 通知 MonitorServer |
| 平级关联 | ScreenCaptureMonitorServer ↔ ScreenCaptureServer — 前者全局监控，后者单实例录制 |
| 平级关联 | ScreenCaptureControllerServer ↔ ScreenCaptureServer — Controller 将用户选择分发到对应 Server 实例 |
| IPC 关联 | [[ipc-layer-entities]] — Monitor/Controller 的 IPC 存根/代理 |

## 数据模型

### ScreenCaptureMonitorServer 数据结构

| 数据结构 | 类型 | 说明 |
|---------|------|------|
| runningCapturePidCounts_ | map\<int32_t, int32_t\> | PID → 录制实例计数（引用计数） |
| screenCaptureMonitorCbSet_ | set\<sptr\<ScreenCaptureMonitorListener\>\> | 已注册监听器集合 |
| systemScreenRecorderPid_ | int32_t | 系统录制器 PID（默认 -1） |

### ScreenCaptureMonitorEvent 枚举

| 值 | 说明 |
|----|------|
| SCREENCAPTURE_STARTED | 0 — 屏幕录制开始 |
| SCREENCAPTURE_STOPPED | 1 — 屏幕录制结束 |
| SCREENCAPTURE_DIED | 2 — 屏幕录制进程死亡 |

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| ScreenCaptureMonitorServer | `services/services/screen_capture_monitor/server/screen_capture_monitor_server.h/.cpp` | ScreenCaptureMonitorServer::GetInstance/CallOnScreenCaptureStarted/CallOnScreenCaptureFinished |
| ScreenCaptureMonitorClient | `services/services/screen_capture_monitor/client/screen_capture_monitor_client.h/.cpp` | ScreenCaptureMonitorClient::Create/IsScreenCaptureWorking |
| ScreenCaptureControllerServer | `services/services/screen_capture/server/screen_capture_controller_server.h/.cpp` | ScreenCaptureControllerServer::ReportAVScreenCaptureUserChoice/GetAVScreenCaptureConfigurableParameters |
| ScreenCaptureControllerClient | `services/services/screen_capture/client/screen_capture_controller_client.h/.cpp` | ScreenCaptureControllerClient::Create/ReportAVScreenCaptureUserChoice |
| ScreenCaptureMonitor (InnerAPI) | `interfaces/inner_api/native/screen_capture_monitor.h` | ScreenCaptureMonitor, ScreenCaptureMonitorListener, ScreenCaptureMonitorEvent |
| ScreenCaptureController (InnerAPI) | `interfaces/inner_api/native/screen_capture_controller.h` | ScreenCaptureController, ScreenCaptureControllerFactory |
| IInnerScreenCaptureMonitorService | `services/include/i_screen_capture_monitor_service.h` | IInnerScreenCaptureMonitorService, IScreenCaptureMonitorService |
| IScreenCaptureController | `services/include/i_screen_capture_controller.h` | IScreenCaptureController |
| ScreenCaptureMonitorCallback | `frameworks/js/screencapturemonitor/screen_capture_monitor_callback.cpp/.h` | ScreenCaptureMonitorCallback |
| ScreenCaptureMonitorNapi | `frameworks/js/screencapturemonitor/screen_capture_monitor_napi.cpp/.h` | ScreenCaptureMonitorNapi |

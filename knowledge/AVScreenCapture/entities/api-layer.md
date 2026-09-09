# API 接入层实体

> AVScreenCapture / OH_AVScreenCapture / CJAVScreenCapture 等 API 层核心类与接口

## 实体概念

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| AVScreenCapture (ArkTS/JS) | ArkTS/JS 屏幕录制公开 API 类 | Init(config) 初始化配置；StartRecording/StopRecording/PauseRecording/ResumeRecording 录制控制；PresentPicker 弹出选择器；on('stateChange')/on('error') 事件回调；TaskQueue 异步调度 | 公开 API 类 |
| OH_AVScreenCapture (C API) | C 语言屏幕录制公开 API，740 行头文件 | OH_AVScreenCapture_Create/Release 生命周期；OH_AVScreenCapture_Init 初始化；OH_AVScreenCapture_StartScreenCapture/StartScreenRecording 采集/录制；OH_AVScreenCapture_SetStateCallback/SetDataCallback/SetErrorCallback 新回调；OH_AVScreenCapture_SetCallback 旧回调（deprecated since 12）；since 10~26 持续扩展 | 公开 API (C) |
| CJAVScreenCapture (CangJie FFI) | 仓颉语言屏幕录制 FFI 导出 | FFI_EXPORT 导出；CreateAVScreenCaptureRecorder 创建实例；AVScreenCaptureinit/StartRecording/StopRecording/Release 调用；OnStateChange/OnError 回调注册 | 公开 API (CangJie) |
| ScreenCapture (InnerAPI) | 内部抽象接口，40+ 纯虚函数 | Init/StartScreenCapture/StopScreenCapture/Release 生命周期；SetMicrophoneEnabled/SetCanvasRotation/ShowCursor/ResizeCanvas 参数控制；AcquireAudioBuffer/AcquireVideoBuffer/ReleaseAudioBuffer/ReleaseVideoBuffer 缓冲管理；PauseScreenCapture/ResumeScreenCapture 暂停恢复；AddWatermark/AddWhiteListWindows/ExcludeContent 高级特性 | 内部抽象接口 |
| ScreenCaptureCallBack (回调基类) | 屏幕录制回调基类，8 个虚函数 | OnError 错误回调；OnAudioBufferAvailable/OnVideoBufferAvailable 缓冲就绪；OnStateChange 状态变更；OnDisplaySelected 显示选择；OnCaptureContentChanged 内容变更；OnUserSelected 用户选择；OnPrivacyProtect 隐私保护 | 回调基类 |
| ScreenCaptureImpl | Native 层屏幕录制实现 | 持有 IScreenCaptureService 代理；Init 按 dataType_ 分发 InitOriginalStream/InitCaptureFile；SetScreenCaptureCallback 设置回调；AcquireAudioBuffer/AcquireVideoBuffer 获取缓冲；HiTraceId 传递 | 内部实现类 |
| ScreenCaptureFactory | 屏幕录制工厂 | CreateScreenCapture() 创建实例；CreateScreenCapture(AppInfo) 带 SA 信息创建 | 工厂类 |
| ScreenCaptureObject | C API 屏幕录制包装 | 持有 shared_ptr\<ScreenCapture\> + shared_ptr\<NativeScreenCaptureCallback\>；isStart 标志 | C API 包装类 |
| NativeScreenCaptureCallback | C API 回调适配，新旧两套回调 | 旧回调 callback_ (OH_AVScreenCaptureCallback 函数指针集)；新回调 errorCallback_/stateChangeCallback_/dataCallback_/contentChangedCallback_/displaySelectedCallback_/userSelectedCallback_/privacyProtectCallback_；shared_mutex 线程安全；isBufferAvailableCallbackStop_ 控制缓冲回调停止 | 回调适配类 |
| NativeScreenCaptureDataCallback | C API 数据回调适配，自动获取/释放 Buffer | OnBufferAvailable 按 bufferType 分发 OnProcessVideoBuffer/OnProcessAudioBuffer；AcquireAudioBuffer/AcquireVideoBuffer 自动获取并封装 OH_AVBuffer；ReleaseAudioBuffer/ReleaseVideoBuffer 自动释放 | 数据回调适配类 |
| AVScreenCaptureNapi | NAPI 桥接类 | JsCreateAVScreenRecorder 创建；JsInit/JsStartRecording/JsStopRecording 异步 Promise；JsSetEventCallback/JsCancelEventCallback 事件注册；taskQFuncs_ 映射表 + TaskQueue 异步 | NAPI 桥接类 |
| AVScreenCaptureCallback | NAPI 回调适配 | OnError/OnStateChange 桥接；uv_async_simplify 投递 JS 线程；refMap_ 管理回调引用 | NAPI 回调适配 |
| ScreenCaptureMonitor (InnerAPI 单例) | 屏幕录制监控单例 | GetInstance() 获取单例；IsScreenCaptureWorking() 查询运行中 PID 列表；RegisterScreenCaptureMonitorListener/Unregister 注册注销监听器；IsSystemScreenRecorder/IsSystemScreenRecorderWorking 系统录制器查询 | 内部单例 |
| ScreenCaptureMonitorImpl | Monitor Native 实现 | 持有 IScreenCaptureMonitorService 代理；Init/InitInner 初始化 | Native 实现类 |
| ScreenCaptureMonitorNapi | Monitor NAPI 桥接 | JsGetScreenCaptureMonitor 获取；JsSetEventCallback/JsCancelEventCallback 事件注册；JsIsSystemScreenRecorderWorking 属性查询 | NAPI 桥接类 |
| ScreenCaptureMonitorCallback | Monitor NAPI 回调适配 | OnScreenCaptureStarted/OnScreenCaptureFinished/OnScreenCaptureDied 桥接；uv_async 投递 JS 线程 | NAPI 回调适配 |
| ScreenCaptureController (InnerAPI) | 用户选择控制器抽象接口 | ReportAVScreenCaptureUserChoice(sessionId, choice) 上报用户选择；GetAVScreenCaptureConfigurableParameters(sessionId, resultStr) 获取可配置参数 | 内部抽象接口 |
| ScreenCaptureControllerImpl | Controller Native 实现 | ReportAVScreenCaptureUserChoice/GetAVScreenCaptureConfigurableParameters 透传 | Native 实现类 |
| ScreenCaptureControllerFactory | Controller 工厂 | CreateScreenCaptureController() 创建实例 | 工厂类 |

### 桥接层实体

| 实体名称 | 实体定义 | 核心特征 |
|---------|---------|---------|
| NAPI 桥接层 | JS API → NAPI → ScreenCaptureImpl 桥接 | TaskQueue 异步调度，uv_async 投递回调 JS 主线程 |
| CJ-FFI 桥接层 | 仓颉语言 FFI 桥接 | FFI_EXPORT 导出，FFIData 继承，callbackId 回调机制 |
| Taihe 框架桥接层 | Taihe 框架桥接层 | ANI 桥接 |

## 上下文与场景

### 交互流程

**AVScreenCapture (ArkTS/JS) 调用链路**：

```
应用 (ArkTS/JS)
  → AVScreenCaptureNapi
  → ScreenCaptureImpl
  → IPC (ScreenCaptureClient)
  → ScreenCaptureServer
  → 虚拟屏幕 + AudioCapturer + Recorder
```

**OH_AVScreenCapture (C API) 调用链路**：

```
应用 (C)
  → OH_AVScreenCapture_*
  → ScreenCaptureObject (持有 ScreenCapture + NativeScreenCaptureCallback)
  → ScreenCaptureImpl
  → IPC → ScreenCaptureServer → 虚拟屏幕/音频采集
```

**CJAVScreenCapture (CangJie) 调用链路**：

```
应用 (CangJie)
  → FFI_EXPORT CJAVScreenCapture
  → ScreenCapture (ScreenCaptureFactory::CreateScreenCapture)
  → ScreenCaptureImpl
  → IPC → ScreenCaptureServer
```

### 使用场景

| 实体 | 适用场景 |
|------|---------|
| AVScreenCapture | ArkTS/JS 应用屏幕录制（文件录制/流式采集） |
| OH_AVScreenCapture | C/C++ 应用屏幕录制（since 10） |
| CJAVScreenCapture | 仓颉语言应用屏幕录制 |
| ScreenCaptureMonitor | 监控系统是否有屏幕录制正在进行 |
| ScreenCaptureController | Picker 用户选择结果上报 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 业务规则 | AVScreenCapture 必须先 Init(config) 再 StartRecording，非法顺序返回错误 |
| 业务规则 | OH_AVScreenCapture 新回调（SetStateCallback/SetDataCallback/SetErrorCallback）since 12，旧 SetCallback since 10 已 deprecated |
| 安全与隐私约束 | 屏幕录制需要用户隐私授权弹窗，未授权时不可采集 |
| 线程安全 | NativeScreenCaptureCallback 使用 shared_mutex 保护新旧两套回调的并发访问 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 下游影响 | [[service-layer]] — API 层通过 IPC 调用服务层 |
| 下游影响 | [[ipc-layer-entities]] — API 层通过 ScreenCaptureClient 发起 IPC |
| 平级关联 | AVScreenCapture vs OH_AVScreenCapture — 同一录制能力不同语言接口，内部均走 ScreenCaptureImpl |
| 概念对比 | ScreenCaptureMonitor (InnerAPI 单例) vs ScreenCapture (实例接口) — 前者全局监控，后者单实例录制 |

## 数据模型

### AVScreenCaptureConfig

屏幕录制核心配置结构体：

| 字段 | 说明 |
|------|------|
| captureMode | 采集模式（CAPTURE_HOME_SCREEN/CAPTURE_SPECIFIED_SCREEN/CAPTURE_SPECIFIED_WINDOW/CAPTURE_VIRTUAL_EXTENDED_SCREEN/CAPTURE_SPECIFIED_APP） |
| dataType | 数据类型（ORIGINAL_STREAM/ENCODED_STREAM/CAPTURE_FILE） |
| audioInfo | 音频信息（micCapInfo + innerCapInfo + audioEncInfo） |
| videoInfo | 视频信息（videoCapInfo + videoEncInfo） |
| recorderInfo | 录制文件信息（url + fileFormat） |
| strategy | 采集策略（enableDeviceLevelCapture/keepCaptureDuringCall/pickerPopUp/fillMode/enablePause 等） |
| highlightConfig | 高亮配置（lineThickness/lineColor/mode） |

### 关键枚举

| 枚举 | 值 |
|------|----|
| AudioCaptureSourceType | SOURCE_INVALID/SOURCE_DEFAULT/MIC/ALL_PLAYBACK/APP_PLAYBACK |
| DataType | ORIGINAL_STREAM/ENCODED_STREAM/CAPTURE_FILE/INVAILD |
| CaptureMode | CAPTURE_HOME_SCREEN/CAPTURE_SPECIFIED_SCREEN/CAPTURE_SPECIFIED_WINDOW/CAPTURE_VIRTUAL_EXTENDED_SCREEN/CAPTURE_SPECIFIED_APP |
| AVScreenCaptureStateCode | SCREEN_CAPTURE_STATE_STARTED/CANCELED/STOPPED_BY_USER/INTERRUPTED_BY_OTHER/STOPPED_BY_CALL/MIC_UNAVAILABLE/MIC_MUTED/UNMUTED/ENTER_PRIVATE_SCENE/EXIT_PRIVATE_SCENE/STOPPED_BY_USER_SWITCHES/PAUSED_BY_USER/RESUMED_BY_USER/PAUSED_BY_APP/RESUMED_BY_APP |
| AVScreenCaptureBufferType | SCREEN_CAPTURE_BUFFERTYPE_VIDEO/AUDIO_INNER/AUDIO_MIC |

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| ScreenCapture (InnerAPI) | `interfaces/inner_api/native/screen_capture.h` | ScreenCapture, ScreenCaptureCallBack, ScreenCaptureFactory |
| ScreenCaptureController (InnerAPI) | `interfaces/inner_api/native/screen_capture_controller.h` | ScreenCaptureController, ScreenCaptureControllerFactory |
| ScreenCaptureMonitor (InnerAPI) | `interfaces/inner_api/native/screen_capture_monitor.h` | ScreenCaptureMonitor, ScreenCaptureMonitorListener |
| OH_AVScreenCapture (C API) | `interfaces/kits/c/native_avscreen_capture.h` | OH_AVScreenCapture_* 函数族 |
| ScreenCaptureImpl | `frameworks/native/screen_capture/screen_capture_impl.cpp/.h` | ScreenCaptureImpl::Init/StartScreenCapture |
| ScreenCaptureMonitorImpl | `frameworks/native/screen_capture/screen_capture_monitor_impl.cpp/.h` | ScreenCaptureMonitorImpl |
| ScreenCaptureControllerImpl | `frameworks/native/screen_capture/screen_capture_controller_impl.cpp/.h` | ScreenCaptureControllerImpl |
| ScreenCaptureObject | `frameworks/native/capi/screencapture/native_avscreen_capture.cpp` | ScreenCaptureObject, NativeScreenCaptureCallback |
| NativeScreenCaptureCallback | `frameworks/native/capi/screencapture/native_avscreen_capture.cpp` L350-L498 | NativeScreenCaptureCallback, shared_mutex |
| NativeScreenCaptureDataCallback | `frameworks/native/capi/screencapture/native_avscreen_capture.cpp` 第89-第348行 | NativeScreenCaptureDataCallback |
| AVScreenCaptureNapi | `frameworks/js/avscreen_capture/avscreen_capture_napi.cpp/.h` | AVScreenCaptureNapi, taskQFuncs_ |
| AVScreenCaptureCallback | `frameworks/js/avscreen_capture/avscreen_capture_callback.cpp/.h` | AVScreenCaptureCallback |
| ScreenCaptureMonitorNapi | `frameworks/js/screencapturemonitor/screen_capture_monitor_napi.cpp/.h` | ScreenCaptureMonitorNapi |
| ScreenCaptureMonitorCallback | `frameworks/js/screencapturemonitor/screen_capture_monitor_callback.cpp/.h` | ScreenCaptureMonitorCallback |
| CJAVScreenCapture | `frameworks/cj/avscreen_capture/include/cj_avscreen_capture.h` | CJAVScreenCapture, FFI_EXPORT |
| CJAVScreenCaptureCallback | `frameworks/cj/avscreen_capture/include/cj_avscreen_capture_callback.h` | CJAVScreenCaptureCallback |

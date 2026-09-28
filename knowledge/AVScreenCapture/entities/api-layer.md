# API 接入层实体

> AVScreenCapture / OH_AVScreenCapture / CJAVScreenCapture 等 API 层核心类与接口

## 实体概念

| 实体名称 | 实体定义 | 类型/分类 |
|---------|---------|----------|
| AVScreenCapture (ArkTS/JS) | ArkTS/JS 屏幕录制公开 API 类 | 公开 API 类 |
| OH_AVScreenCapture (C API) | C 语言屏幕录制公开 API（since 10，持续扩展至 26） | 公开 API (C) |
| CJAVScreenCapture (CangJie FFI) | 仓颉语言屏幕录制 FFI 导出 | 公开 API (CangJie) |
| ScreenCapture (InnerAPI) | 内部抽象接口，定义生命周期/采集控制/缓冲管理/高级特性 | 内部抽象接口 |
| ScreenCaptureCallBack (回调基类) | 8 个回调虚函数 | 回调基类 |
| ScreenCaptureImpl | Native 层实现，持有服务代理，转发调用到服务端 | 内部实现类 |
| ScreenCaptureFactory | 实例创建工厂 | 工厂类 |
| ScreenCaptureObject | C API 包装，持有实现与回调 | C API 包装类 |
| NativeScreenCaptureCallback | C API 回调适配，兼容新旧两套回调（旧 SetCallback since 10 deprecated，新 SetState/SetData/SetErrorCallback since 12） | 回调适配类 |
| NativeScreenCaptureDataCallback | C API 数据回调适配，自动获取/释放 Buffer | 数据回调适配类 |
| AVScreenCaptureNapi | NAPI 桥接类，TaskQueue 异步调度 | NAPI 桥接类 |
| AVScreenCaptureCallback | NAPI 回调适配，uv_async 投递 JS 线程 | NAPI 回调适配 |
| ScreenCaptureMonitor (InnerAPI 单例) | 屏幕录制监控单例，查询运行中 PID/系统录制器 | 内部单例 |
| ScreenCaptureMonitorImpl / Napi / Callback | Monitor Native 实现 / NAPI 桥接 / 回调适配 | 客户端实现族 |
| ScreenCaptureController (InnerAPI) | 用户选择控制器抽象接口 | 内部抽象接口 |
| ScreenCaptureControllerImpl / Factory | Controller Native 实现 / 工厂 | 客户端实现族 |

### 桥接层

| 桥接层 | 说明 |
|--------|------|
| NAPI 桥接层 | JS API → NAPI → ScreenCaptureImpl，TaskQueue 异步调度，uv_async 投递回调 JS 主线程 |
| CJ-FFI 桥接层 | 仓颉语言 FFI 桥接，FFI_EXPORT 导出，callbackId 回调机制 |
| Taihe 框架桥接层 | ANI 桥接 |

## 调用链路

**AVScreenCapture (ArkTS/JS)**：
应用 → AVScreenCaptureNapi → ScreenCaptureImpl → IPC(ScreenCaptureClient) → ScreenCaptureServer → 虚拟屏幕 + AudioCapturer + Recorder

**OH_AVScreenCapture (C API)**：
应用 → OH_AVScreenCapture_* → ScreenCaptureObject → ScreenCaptureImpl → IPC → ScreenCaptureServer

**CJAVScreenCapture (CangJie)**：
应用 → FFI_EXPORT CJAVScreenCapture → ScreenCaptureFactory::CreateScreenCapture → ScreenCaptureImpl → IPC → ScreenCaptureServer

## 使用场景

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
| 业务规则 | 必须先 Init(config) 再 StartRecording，非法顺序返回错误 |
| 业务规则 | OH_AVScreenCapture 新回调（SetStateCallback/SetDataCallback/SetErrorCallback）since 12，旧 SetCallback since 10 已 deprecated |
| 安全与隐私约束 | 屏幕录制需要用户隐私授权弹窗，未授权时不可采集 |
| 线程安全 | C API 回调适配使用读写锁保护新旧两套回调的并发访问 |

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

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 下游影响 | [service-layer](service-layer.md) — API 层通过 IPC 调用服务层 |
| 下游影响 | [ipc-layer-entities](ipc-layer-entities.md) — API 层通过 Client 发起 IPC |
| 平级关联 | AVScreenCapture vs OH_AVScreenCapture — 同一录制能力不同语言接口，内部均走 ScreenCaptureImpl |
| 概念对比 | ScreenCaptureMonitor (单例) vs ScreenCapture (实例接口) — 前者全局监控，后者单实例录制 |

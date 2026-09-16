# 业务背景与系统定位

> screen_capture 模块在系统中的定位、核心场景与外部依赖。

## 系统定位

screen_capture 是 player_framework 多媒体子系统的**屏幕录制框架层**，位于应用 API 与底层显示/音频采集能力之间。与 AVPlayer/AVRecorder 不同，screen_capture 不设独立引擎层，直接调用 Rosen 虚拟屏幕采集视频、AudioCapturer 采集音频、复用 Recorder 引擎录制文件：

```
应用层 (ArkTS / C / CangJie 应用)
    ↓
API 层 (AVScreenCapture / AVScreenCaptureMonitor / AVScreenCaptureController)
    ↓
player_framework ← 本框架
    ↓
原子能力层 (Rosen VirtualScreen / AudioStandard AudioCapturer / Recorder引擎)
    ↓
HDI 硬件驱动 (显示合成 / 音频采集 / 编解码)
```

## 核心业务场景

| 场景 | 说明 | 涉及能力 |
|------|------|---------|
| 应用屏幕录制 | 应用发起录屏，输出原始流或录制文件 | AVScreenCapture + Rosen VirtualScreen + AudioCapturer |
| 系统录屏监控 | 系统应用监听全局录屏状态 | AVScreenCaptureMonitor + MonitorServer 单例 |
| 应用内录屏 | 录制指定窗口/应用画面 | AVScreenCapture + CAPTURE_SPECIFIED_WINDOW/APP + Picker |
| 虚拟扩展屏录制 | 录制虚拟扩展显示画面 | AVScreenCapture + CAPTURE_VIRTUAL_EXTENDED_SCREEN |
| 用户选择录屏 | Picker 弹窗让用户选择录制目标 | AVScreenCaptureController + PresentPicker + UserChoice |
| 隐私保护录屏 | 跳过隐私窗口、白名单窗口、内容过滤 | PrivacyProtected + SkipPrivacyMode + ExcludeContent |
| 麦克风+内录混音 | 同时采集麦克风和系统内录音频 | AudioDataSource + MixModeBufferWrite |
| 多显示器录屏 | 镜像指定物理屏幕到虚拟屏幕 | MakeMirror + ChangeMirrorScreen |

## 进程模型

| 进程 | 包含模块 | 说明 |
|------|---------|------|
| 应用进程 | ScreenCaptureImpl / ScreenCaptureMonitorImpl / ScreenCaptureControllerImpl | 客户端代理，持有 IPC Proxy |
| 媒体服务进程 | ScreenCaptureServer / ScreenCaptureServerManager / ScreenCaptureControllerServer / ScreenCaptureMonitorServer | 服务端核心逻辑，常驻 SA |
| 编解码服务进程 | codec_server | 文件录制模式下的视频/音频硬编码 |

**关键约束**：录屏客户端与服务端分进程运行，所有操作必须通过 IPC 完成；视频采集通过 Rosen VirtualScreen 跨进程获取 SurfaceBuffer。

## 技术栈

| 类别 | 技术 | 说明 |
|------|------|------|
| 核心语言 | C++ | 服务端、客户端、采集逻辑 |
| 客户端API | C (C API) / ArkTS / JS / CangJie | AVScreenCapture 等对外 API |
| 桥接层 | NAPI / CJ-FFI / ANI | JS/ArkTS 到 C++ 的桥接 |
| 进程间通信 | OHOS IPC (Binder) | Client-Server 通信，41+3+6 消息码 |
| 视频采集 | Rosen VirtualScreen + Surface | ScreenManager 创建虚拟屏幕，SurfaceBuffer 逐帧获取 |
| 音频采集 | AudioStandard::AudioCapturer | AudioCapturerWrapper 封装，支持麦克风/内录/混音 |
| 文件录制 | Recorder 引擎 (IRecorderService) | 复用 player_framework RecorderServer |
| 隐私保护 | PrivacyKit + WindowManager | 权限申请、隐私窗口检测、跳过保护 |
| 日志 | HiLog | 分模块标签日志 |
| 打点 | HiSysEvent + StatisticalEventInfo | 录屏统计与故障诊断 |

## 外部依赖

| 依赖 | 提供方 | 用途 |
|------|--------|------|
| Rosen ScreenManager | graphic | 创建/销毁虚拟屏幕、镜像、显示器管理 |
| Rosen WindowManager | graphic | 窗口信息查询、隐私窗口检测、会话生命周期监听 |
| AudioCapturer | multimedia/audio_framework | 麦克风/内录音频采集 |
| Surface | graphic | SurfaceBuffer 视频帧缓冲、Producer/Consumer 模型 |
| PrivacyKit | access_token | CAPTURE_SCREEN 权限申请/释放/记录 |
| AbilityRuntime | ability_runtime | Picker UIExtensionAbility 连接、用户选择弹窗 |
| WindowManager | window_manager | 窗口白名单、隐私窗口变更监听 |
| NotificationService | notification | 录屏通知栏发布/更新/移除 |
| AccountManager | account_os_account | 账号切换监听（录屏中断） |
| RecorderServer | player_framework | 文件录制模式复用 Recorder 引擎 |
| AudioPolicyManager | audio_framework | 音频渲染器状态监听、通话中断处理 |

## API 层次

```
┌─────────────────────────────────────────┐
│  ArkTS/JS API                           │  ← 应用开发者使用
│  AVScreenCapture                        │
│  AVScreenCaptureMonitor                 │
├─────────────────────────────────────────┤
│  C API                                  │  ← Native开发者使用
│  OH_AVScreenCapture                     │
├─────────────────────────────────────────┤
│  Inner API                              │  ← 系统内部使用
│  IScreenCaptureService                  │
│  IScreenCaptureController               │
│  IScreenCaptureMonitorService           │
│  ScreenCapture / ScreenCaptureCallBack  │
└─────────────────────────────────────────┘
```

## 知识关联

- [[architecture]] - 架构总览
- [[glossary]] - 术语速查

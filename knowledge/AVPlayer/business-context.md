# 业务背景与系统定位

> player_framework 在系统中的定位、核心场景与外部依赖。

## 系统定位

player_framework 是 OpenHarmony 多媒体子系统的**播放/录制/转码框架层**，位于应用 API 与底层编解码能力之间：

```
应用层 (ArkTS / C / C++ 应用)
    ↓
API 层 (AVPlayer / AVRecorder / AVScreenCapture / AVTranscoder)
    ↓
player_framework ← 本框架
    ↓
原子能力层 (MediaDemuxer / MediaCodec / VideoDecoder / AudioRenderer)
    ↓
插件层 (ffmpeg Demuxer / hcodec fcodec / HLS Downloader)
    ↓
Media_Foundation (AVBuffer / PluginManager / FilterFactory)
```

## 核心业务场景

| 场景 | 说明 | 涉及能力 |
|------|------|---------|
| 本地音视频播放 | 播放本地文件（mp4/mkv/flac等） | AVPlayer + Histreamer引擎 |
| 网络流播放 | 播放HTTP/HLS/DASH等网络流 | AVPlayer + Source插件 + HLS/DASH解析 |
| 低功耗音频播放 | 后台音乐播放，降低功耗 | AVPlayer + LPP引擎 |
| 音视频录制 | 录制音频/视频到文件 | AVRecorder + 编码器 |
| 屏幕录制 | 录制屏幕内容 | AVScreenCapture |
| 音视频转码 | 格式转换/编码参数调整 | AVTranscoder |
| 元数据提取 | 获取媒体文件信息/缩略图 | AVMetadataHelper / AVImageGenerator |
| DRM 内容播放 | 受保护内容的解密播放 | AVPlayer + DRM集成 |

## 进程模型

| 进程 | 包含模块 | 说明 |
|------|---------|------|
| 应用进程 | PlayerClient / RecorderClient | 播放器客户端代理 |
| 媒体服务进程 | PlayerServer / RecorderServer / ScreenCaptureServer | 服务端核心逻辑，常驻 |
| 编解码服务进程 | codec_server | 视频硬解独立进程 |

**关键约束**：播放器客户端与服务端分进程运行，所有操作必须通过IPC完成。

## 技术栈

| 类别 | 技术 | 说明 |
|------|------|------|
| 核心语言 | C++ | 服务端、引擎、Pipeline |
| 客户端API | C (C API) / ArkTS / JS | AVPlayer等对外API |
| 桥接层 | NAPI / CJ-FFI / ANI | JS/ArkTS到C++的桥接 |
| 进程间通信 | OHOS IPC (Binder) | Client-Server通信 |
| 数据传递 | AVBufferQueue | Pipeline Filter间数据流转 |
| 插件加载 | dlopen/dlsym | 动态加载引擎和编解码插件 |
| 媒体处理 | ffmpeg (软解) / hcodec fcodec (硬解) | 编解码实现 |
| 日志 | HiLog | 分模块标签日志 |
| 打点 | HiSysEvent | 行为统计与故障诊断 |

## 外部依赖

| 依赖 | 提供方 | 用途 |
|------|--------|------|
| AVCodec 服务 | multimedia/av_codec | 视频硬件解码(codec_server进程) |
| AudioRenderer | multimedia/audio_framework | 音频输出渲染 |
| Surface | graphic | 视频画面渲染 |
| DRM | drm_framework | 内容解密 |
| AVSession | avsession | 后台播放控制、媒体会话 |
| Media_Foundation | media_foundation | Pipeline基础组件(AVBuffer/PluginManager/FilterFactory) |

## API 层次

```
┌─────────────────────────────────────────┐
│  ArkTS/JS API                           │  ← 应用开发者使用
│  AVPlayer / AVRecorder / AVTranscoder   │
├─────────────────────────────────────────┤
│  C API                                  │  ← Native开发者使用
│  OH_AVPlayer / OH_AVRecorder            │
├─────────────────────────────────────────┤
│  Inner API                              │  ← 系统内部使用
│  IPlayer / IPlayerEngine / IRecorder    │
└─────────────────────────────────────────┘
```

## 知识关联

- [[architecture]] - 架构总览
- [[glossary]] - 术语速查

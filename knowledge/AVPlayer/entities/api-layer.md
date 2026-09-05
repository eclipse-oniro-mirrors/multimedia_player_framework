# API 接入层实体

> AVPlayer/AVRecorder/AVTranscoder 等 API 层核心类与接口

## 实体概念

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| AVPlayer (ArkTS/JS) | ArkTS/JS 播放器公开 API 类 | url/fdSrc/dataSrc 媒体源设置；Play/Pause/Stop/Seek/SetVolume/SetSpeed/SetLooping/SelectTrack 播放控制；on('stateChange')/on('error')/on('info')/on('seekDone') 事件回调 | 公开 API 类 |
| OH_AVPlayer (C API) | C 语言播放器公开 API | OH_AVPlayer_Create/Release 生命周期管理；OH_AVPlayer_SetURLSource/SetFDSource 媒体源设置；OH_AVPlayer_Seek/SetVolume/SetPlayerCallback 播放控制；OH_AVPlayer_SetMediaSource/SetPlaybackStrategy 高级特性 | 公开 API (C) |
| AVRecorder (ArkTS/JS + C API) | 音视频录制公开 API | prepare(config) 准备配置，getInputSurface 获取输入 Surface，生命周期方法；C API: OH_AVRecorder_* 函数族 | 公开 API 类 |
| AVTranscoder (ArkTS + C API) | 音视频转码公开 API | 转码流水线（解封装→解码→编码→封装），支持水印 | 公开 API 类 |
| AVMetadataExtractor (ArkTS) | 元数据提取公开 API | fdSrc/dataSrc 媒体源；resolveMetadata 解析元数据，fetchAlbumCover 获取专辑封面，fetchFrameByTime 按时间获取帧 | 公开 API 类 |
| AVMetadataHelper (内部 API) | 元数据提取内部 API | SetSource 设置源，ResolveMetadata 解析元数据，FetchFrameAtPosition 按位置获取帧 | 内部 API |
| AVImageGenerator / OH_AVImageGenerator | 视频缩略图/关键帧提取 API | Seek + AVCodecVideoDecoder 解码，SEEK_CLOSEST 最近帧定位 | 公开 API (ArkTS + C) |
| OH_LowPowerAudioSink / OH_LowPowerVideoSink | LPP 低功耗输出端 C API | 低功耗音频/视频输出 | LPP 专用 C API |
| PlayerImpl | Native 层播放器实现 | SetSource(url/fd/dataSrc) 设置源，PrepareAsync 异步准备，Play/Pause/Stop/SeekForInt64 播放控制；PlayerImplCallback → OnInfo/OnError 桥接应用回调 | 内部实现类 |
| PlayerFactory | 播放器工厂 | CreatePlayer(producer) 支持 INNER/CAPI 两种生产者模式 | 工厂类 |
| PlayerObject | C API 播放器包装 | 持有 PlayerImpl + NativeAVPlayerCallback | C API 包装类 |
| NativeAVPlayerCallback | C API 回调分发 | onInfoFuncs_ 映射表路由不同信息类型到对应回调函数 | 回调分发类 |

### 桥接层实体

| 实体名称 | 实体定义 | 核心特征 |
|---------|---------|---------|
| NAPI 桥接层 | JS API → NAPI → PlayerImpl 桥接 | TaskQueue 异步调度，napi_send_event 回调 JS 主线程 |
| CJ-FFI 桥接层 | 仓颉语言 FFI 桥接 | 仓颉语言互操作 |
| Taihe 框架桥接层 | Taihe 框架桥接层 | ANI 桥接 |

## 上下文与场景

### 交互流程

**AVPlayer (ArkTS/JS) 调用链路**：

```
应用 (ArkTS/JS)
  → AVPlayer NAPI 类
  → PlayerImpl
  → IPC (PlayerClient)
  → PlayerServer
  → 引擎工厂 → HiPlayerImpl
  → 流水线 → HDI
```

**OH_AVPlayer (C API) 调用链路**：

```
应用 (C)
  → OH_AVPlayer_*
  → PlayerObject (持有 PlayerImpl + NativeAVPlayerCallback)
  → PlayerImpl
  → IPC → PlayerServer → 流水线
```

**AVMetadataExtractor 调用链路**：

```
应用 (ArkTS)
  → AVMetadataExtractor NAPI
  → avmetadatahelper-impl
  → MediaDemuxer + AVMetaDataCollector + AVThumbnailGenerator
```

### 使用场景

| 实体 | 适用场景 |
|------|---------|
| AVPlayer | ArkTS/JS 应用音视频播放 |
| OH_AVPlayer | C/C++ 应用音视频播放 |
| AVRecorder | 音视频录制（摄像头+麦克风） |
| AVTranscoder | 音视频转码（格式转换/压缩/水印） |
| AVMetadataExtractor | 媒体元数据提取（标题/艺术家/封面） |
| AVImageGenerator | 视频缩略图/关键帧提取 |
| OH_LowPowerAudioSink/VideoSink | LPP 低功耗播放场景 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 业务规则 | AVPlayer 状态机约束：必须按 空闲→设置源→准备→播放 顺序调用，非法顺序返回错误 |
| 业务规则 | OH_AVPlayer 与 AVPlayer 功能对齐，但回调机制不同（C 函数指针 vs ArkTS 事件） |
| 安全与隐私约束 | dataSrc 媒体源需应用自行管理数据安全，框架不持久化数据内容 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 下游影响 | [[service-layer]] — API 层通过 IPC 调用服务层 |
| 下游影响 | [[ipc-layer-entities]] — API 层通过 PlayerClient 发起 IPC |
| 平级关联 | AVPlayer vs OH_AVPlayer — 同一播放能力不同语言接口，内部均走 PlayerImpl |
| 概念对比 | AVMetadataExtractor (ArkTS 公开) vs AVMetadataHelper (内部 API) — 前者面向应用，后者面向框架内部 |

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| AVPlayer (ArkTS/JS) | `interfaces/kits/js/avplayer_napi.h` | AVPlayer NAPI 类 |
| OH_AVPlayer (C API) | `frameworks/native/capi/player/native_avplayer.cpp` | OH_AVPlayer_* 函数族、PlayerObject |
| AVRecorder (ArkTS) | `interfaces/kits/js/avrecorder_napi.h` | AVRecorder NAPI 类 |
| AVRecorder (C API) | `interfaces/kits/c/avrecorder.h` | OH_AVRecorder_* 函数族 |
| AVTranscoder | `interfaces/kits/c/avtranscoder.h` | OH_AVTranscoder_* 函数族 |
| AVImageGenerator | `interfaces/kits/c/avimage_generator.h` | OH_AVImageGenerator_* 函数族 |
| OH_LowPowerAudioSink | `interfaces/kits/c/lowpower_audio_sink.h` | OH_LowPowerAudioSink_* |
| OH_LowPowerVideoSink | `interfaces/kits/c/lowpower_video_sink.h` | OH_LowPowerVideoSink_* |
| PlayerImpl | `frameworks/native/player/player_impl.cpp/.h` | PlayerImpl::SetSource/PrepareAsync/Play |
| PlayerFactory | `frameworks/native/player/player_impl.cpp` L42-L56 | PlayerFactory::CreatePlayer |
| PlayerObject | `frameworks/native/capi/player/` | PlayerObject |
| NativeAVPlayerCallback | `frameworks/native/capi/player/native_avplayer.cpp` L334-L400 | onInfoFuncs_ |
| NAPI 桥接层 | `frameworks/js/napi/` | TaskQueue, napi_send_event |
| CJ-FFI 桥接层 | `frameworks/cj/` | — |
| Taihe 桥接层 | `frameworks/ani/` | — |

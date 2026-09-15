# AGENTS.md

This file provides guidance to CodeAgent when working with code in this repository.

## 项目概述

Multimedia Player Framework 是 OpenHarmony 多媒体子系统组件，提供音视频播放、录制、转码、录屏等媒体服务的API实现。采用六层架构（API 接入层 → IPC 通信层 → 引擎选择层 → Pipeline 流水线层 → InnerAPI 契约层 → 原子能力+插件层）。

## 技术栈

- **语言**：C++（核心服务/引擎）、ArkTS/JS（客户端 API）、C（Native API / OH_ 系列接口）
- **构建系统**：GN + Ninja
- **进程间通信**：OHOS IPC（MessageParcel / IRemoteStub / SystemAbility）
- **媒体引擎**：Histreamer（Pipeline 架构）、LPP（硬件加速）、ffmpeg（解封装/解码）
- **插件机制**：dlopen 动态加载、PluginManager 注册发现
- **日志与打点**：HiLog、HiSysEvent、HiAppEvent、XCollie
- **目标系统**：OpenHarmony 系统

## 知识库使用规范

项目知识按模块存放在 `knowledge/` 目录下，每个模块独立子目录：

```
knowledge/
├── AVPlayer/          # 播放器模块（已有）
├── AVRecorder/        # 录制模块（已有）
├── AVTranscoder/      # 转码模块（待建设）
├── AVMeta/            # 元数据/缩略图模块（已有）
└── ...                # 其它模块按需扩展
```

### 加载规范

- **启动时加载**：当前模块的 `glossary.md`（术语表）和 `business-context.md`（业务背景）
- **按需加载**：当前模块的 `architecture.md`（架构设计及约束）、`coding-standards.md`（编码规范）

### 术语查询流程

遇到不了解的术语词汇时：

1. 优先在当前模块的 **glossary.md** 中查询
2. 若 glossary 提供了 entity 链接，按需从当前模块的 **entities/** 目录加载术语的详细介绍
3. 若当前模块无该术语，查阅对应技术文档

### 编辑前声明流程

编辑代码前，必须先声明以下信息：

1. **所属模块**：AVPlayer / AVRecorder / AVTranscoder / AVMetadata / 跨模块
2. **任务类别**：API 变更 / 引擎开发 / IPC 修改 / Pipeline 调整 / 内存管理 / DFX 增强 / Bug 修复 / 其它
3. **已读知识文档**：列出已阅读的对应模块 `knowledge/<module>/` 下的相关文档
4. **发现的约束**：从已读文档中提取适用于本次修改的约束规则（引用项目宪法编号或编码铁律编号）

未完成声明前，不得开始编辑代码。

## 知识索引

### AVPlayer 模块（播放器）

知识目录：`knowledge/AVPlayer/`

```
knowledge/AVPlayer/
├── glossary.md                              # 术语表
├── business-context.md                      # 业务背景
├── architecture.md                          # 架构设计及约束
├── coding-standards.md                      # 编码规范
├── entities/
│   ├── api-layer.md                         # API 接入层实体
│   ├── service-layer.md                     # 服务层实体
│   ├── ipc-layer-entities.md                # IPC 层实体
│   ├── engine-layer-entities.md             # 引擎层实体
│   └── engine-factory-and-selection.md      # 引擎工厂与选择
└── technologies/
    ├── player-lifecycle.md                  # 播放器完整生命周期
    ├── seek-architecture.md                 # Seek 完整架构
    ├── ipc-communication.md                 # IPC 通信与回调机制
    ├── playback-features.md                 # 播放控制特性
    ├── memory-and-background.md             # 内存管理与后台策略
    ├── error-handling-and-dfx.md            # 错误处理与 DFX 诊断
    ├── av-sync-and-buffer.md                # 音视频同步与缓冲区管理
    ├── pipeline-architecture.md             # Pipeline 架构与数据流转
    ├── design-patterns.md                   # 设计模式与架构解耦
    ├── media-source-and-protocol.md         # 媒体源与协议
    ├── evolution.md                         # 模块演进记录
    └── flows.md                             # 关键流程详解
```

| 场景 | 先读 | 加载时机 |
|------|------|---------|
| 理解业务术语 | glossary.md | 启动加载 |
| 理解系统定位与外部依赖 | business-context.md | 启动加载 |
| 模块设计 / 引擎开发 / 架构变更 | architecture.md | 按需加载 |
| 编码前必读 | coding-standards.md | 按需加载 |
| API 接入层实体与约束 | entities/api-layer.md | |
| 服务层实体 | entities/service-layer.md | |
| IPC 层实体 | entities/ipc-layer-entities.md | |
| 引擎层实体 | entities/engine-layer-entities.md | |
| 引擎工厂注册与打分选择 | entities/engine-factory-and-selection.md | |
| 播放器完整生命周期 | technologies/player-lifecycle.md | |
| Seek 完整架构 | technologies/seek-architecture.md | |
| IPC 通信与回调机制 | technologies/ipc-communication.md | |
| 播放控制特性 | technologies/playback-features.md | |
| 内存管理与后台策略 | technologies/memory-and-background.md | |
| 错误处理与 DFX 诊断 | technologies/error-handling-and-dfx.md | |
| 音视频同步与缓冲区管理 | technologies/av-sync-and-buffer.md | |
| Pipeline 架构与数据流转 | technologies/pipeline-architecture.md | |
| 设计模式与架构解耦 | technologies/design-patterns.md | |
| 媒体源与协议 | technologies/media-source-and-protocol.md | |
| 模块演进记录 | technologies/evolution.md | |
| 关键流程详解 | technologies/flows.md | |

### AVRecorder 模块（录制）

知识目录：`knowledge/AVRecorder/`

```
knowledge/AVRecorder/
├── glossary.md                              # 术语表
├── business-context.md                      # 业务背景
├── architecture.md                          # 架构设计及约束
├── coding-standards.md                      # 编码规范
├── entities/
│   ├── AVRecorder.md                        # AVRecorder 实体（JS/ArkTS API 行为、NAPI 绑定）
│   ├── RecorderServer.md                    # 录制服务层实体（状态机、配置）
│   ├── HiRecorder.md                        # HiRecorder 引擎实体（Pipeline 构建、Filter 接线）
│   ├── AVRecorderConfig.md                  # 录制配置实体（AVRecorderConfig/AVRecorderProfile）
│   ├── RecorderProfiles.md                  # 录制 Profile 实体
│   ├── SourceId.md                          # Source ID 实体（AUDIO_MASK/VIDEO_MASK/META_MASK）
│   ├── WaterMark.md                         # 水印实体（硬件/软件水印）
│   └── RecorderCallback.md                  # 录制回调实体（IRecorderEngineObs）
└── technologies/
    ├── IPCLayer.md                          # IPC 层技术（Proxy/Stub、回调路由）
    ├── Pipeline.md                          # Pipeline 架构技术（Filter 生命周期、AVBufferQueue 契约）
    ├── AudioVideoCapture.md                 # 音视频采集技术（AudioCaptureFilter/VideoCaptureFilter/Surface）
    ├── WatermarkFusion.md                   # 水印融合技术（OpenGL shader、硬件/软件水印）
    └── Muxer.md                             # 封装技术（MuxerFilter、输出格式、容器写入）
```

| 场景 | 起始路径 | 辅助阅读 |
|------|---------|---------|
| JS/ArkTS API 行为或 NAPI 绑定 | `frameworks/js/avrecorder/` | `knowledge/AVRecorder/entities/AVRecorder.md` |
| 服务层状态机或配置 | `services/services/recorder/server/` | `knowledge/AVRecorder/entities/RecorderServer.md` |
| IPC 客户端/服务端或回调 | `services/services/recorder/ipc/` | `knowledge/AVRecorder/technologies/IPCLayer.md` |
| Pipeline 构建或 Filter 接线 | `services/engine/histreamer/recorder/` | `knowledge/AVRecorder/entities/HiRecorder.md`, `knowledge/AVRecorder/technologies/Pipeline.md` |
| 音频/视频采集 Filter | `av_codec/services/media_engine/filters/audio_capture_filter.*`, `video_capture_filter.*` | `knowledge/AVRecorder/technologies/AudioVideoCapture.md` |
| 音频/视频编码 Filter | `av_codec/services/media_engine/filters/audio_encoder_filter.*`, `surface_encoder_filter.*` | — |
| 水印叠加 | `av_codec/services/media_engine/filters/water_mark_filter.*` | `knowledge/AVRecorder/entities/WaterMark.md`, `knowledge/AVRecorder/technologies/WatermarkFusion.md` |
| 封装/容器写入 | `av_codec/services/media_engine/filters/muxer_filter.*` | `knowledge/AVRecorder/technologies/Muxer.md` |
| Source ID 或 source type 逻辑 | `services/engine/histreamer/recorder/recorder_utils.h` | `knowledge/AVRecorder/entities/SourceId.md` |
| 录制配置或 Profile | `frameworks/js/avrecorder/avrecorder_napi.h`（AVRecorderConfig/AVRecorderProfile） | `knowledge/AVRecorder/entities/AVRecorderConfig.md`, `knowledge/AVRecorder/entities/RecorderProfiles.md` |
| 错误回调或信息上报 | `services/services/engine_intf/i_recorder_engine.h`（IRecorderEngineObs） | `knowledge/AVRecorder/entities/RecorderCallback.md` |
| MediaLibrary 适配器（自动创建文件） | `services/services/recorder/server/media_library_adapter.*` | — |
| 测试 | `test/unittest/` | — |

### AVTranscoder 模块（转码）

知识目录：`knowledge/AVTranscoder/`

```
knowledge/AVTranscoder/
├── glossary.md                              # 术语表
├── business-context.md                      # 业务背景
├── architecture.md                          # 架构设计及约束
├── coding-standards.md                      # 编码规范
├── entities/
│   ├── api-layer.md                         # API 接入层实体
│   ├── service-layer.md                     # 服务层实体
│   ├── ipc-layer-entities.md                # IPC 层实体
│   ├── engine-layer-entities.md             # 引擎层实体
│   └── engine-factory-and-selection.md      # 引擎工厂与选择
└── technologies/
    ├── transcoder-lifecycle.md              # 转码器完整生命周期
    ├── transcoder-pipeline-architecture.md  # Pipeline 架构与数据流转
    ├── watermark-and-video-processing.md    # 水印与视频处理
    ├── transcoder-callback-and-progress.md  # 回调与进度上报
    ├── transcoder-ipc-communication.md      # IPC 通信与回调机制
    ├── transcoder-config-and-formats.md     # 配置与格式支持
    ├── transcoder-state-machine.md          # 状态机与设计模式
    ├── transcoder-error-handling-and-dfx.md # 错误处理与 DFX 诊断
    ├── transcoder-flows.md                  # 关键流程详解
    └── transcoder-evolution.md              # 模块演进记录
```

| 场景 | 先读 | 加载时机 |
|------|------|---------|
| 理解业务术语 | glossary.md | 启动加载 |
| 理解系统定位与外部依赖 | business-context.md | 启动加载 |
| 模块设计 / 引擎开发 / 架构变更 | architecture.md | 按需加载 |
| 编码前必读 | coding-standards.md | 按需加载 |
| API 接入层实体与约束 | entities/api-layer.md | |
| 服务层实体 | entities/service-layer.md | |
| IPC 层实体 | entities/ipc-layer-entities.md | |
| 引擎层实体 | entities/engine-layer-entities.md | |
| 引擎工厂注册与打分选择 | entities/engine-factory-and-selection.md | |
| 转码器完整生命周期 | technologies/transcoder-lifecycle.md | |
| Pipeline 架构与数据流转 | technologies/transcoder-pipeline-architecture.md | |
| 水印与视频处理 | technologies/watermark-and-video-processing.md | |
| 回调与进度上报 | technologies/transcoder-callback-and-progress.md | |
| IPC 通信与回调机制 | technologies/transcoder-ipc-communication.md | |
| 配置与格式支持 | technologies/transcoder-config-and-formats.md | |
| 状态机与设计模式 | technologies/transcoder-state-machine.md | |
| 错误处理与 DFX 诊断 | technologies/transcoder-error-handling-and-dfx.md | |
| 关键流程详解 | technologies/transcoder-flows.md | |
| 模块演进记录 | technologies/transcoder-evolution.md | |

#### AVTranscoder 相关路径

| 修改路径 | 必读文档 | 原因 |
|----------|---------|------|
| frameworks/native/transcoder/ | knowledge/AVTranscoder/entities/api-layer.md | API 层实体与约束，TransCoder/TransCoderImpl InnerAPI 实现 |
| frameworks/native/capi/avtranscoder/ | knowledge/AVTranscoder/entities/api-layer.md | C API 封装约束，OH_AVTranscoder 回调机制、配置结构 |
| frameworks/js/avtranscoder/ | knowledge/AVTranscoder/entities/api-layer.md | NAPI 桥接层调用链，AVTransCoderNapi/AVTransCoderCallback |
| frameworks/cj/avtranscoder/ | knowledge/AVTranscoder/entities/api-layer.md | CJ-FFI 桥接层，CJAVTranscoder/CJAVTranscoderCallback |
| frameworks/taihe/media/ | knowledge/AVTranscoder/entities/api-layer.md | Taihe 桥接层，AVTranscoderImpl async/promise |
| interfaces/inner_api/native/transcoder.h | knowledge/AVTranscoder/entities/api-layer.md | InnerAPI 契约定义，TransCoder/TransCoderCallback/TransCoderFactory |
| interfaces/kits/c/avtranscoder.h | knowledge/AVTranscoder/entities/api-layer.md | C API 公共接口定义，OH_AVTranscoder_State 枚举 |
| services/services/transcoder/server/ | knowledge/AVTranscoder/entities/service-layer.md + knowledge/AVTranscoder/technologies/transcoder-lifecycle.md | 6 状态状态机、TaskQueue 同步队列、ConfigInfo |
| services/services/transcoder/client/ | knowledge/AVTranscoder/entities/ipc-layer-entities.md | IPC 客户端代理，MonitorClientObject 心跳 |
| services/services/transcoder/ipc/ | knowledge/AVTranscoder/technologies/transcoder-ipc-communication.md + knowledge/AVTranscoder/entities/ipc-layer-entities.md | IPC 序列化约束、FD 传递、Monitor 心跳、Stub 销毁 |
| services/engine/histreamer/transcoder/ | knowledge/AVTranscoder/technologies/transcoder-pipeline-architecture.md + knowledge/AVTranscoder/entities/engine-layer-entities.md | Pipeline 动态搭建、VideoProcessMode、Surface 级联、HiTransCoderCallbackLooper |

#### AVTranscoder 高频修改场景→源码文件映射

| 修改场景 | 涉及源码文件 | 必读知识文档 |
|----------|------------|------------|
| 状态机调整 | `transcoder_server.cpp` | knowledge/AVTranscoder/technologies/transcoder-state-machine.md + knowledge/AVTranscoder/entities/service-layer.md |
| IPC 接口增删 | `transcoder_service_stub.cpp`、`transcoder_service_proxy.cpp`、`transcoder_listener_proxy.cpp`、`transcoder_listener_stub.cpp` | knowledge/AVTranscoder/technologies/transcoder-ipc-communication.md + knowledge/AVTranscoder/entities/ipc-layer-entities.md |
| 引擎注册/选择 | `engine_factory_repo.cpp`、`hst_engine_factory.cpp` | knowledge/AVTranscoder/entities/engine-factory-and-selection.md |
| Pipeline Filter 新增/修改 | 对应 `*_filter.cpp` + `hi_transcoder_pipeline.cpp`（av_codec） | knowledge/AVTranscoder/technologies/transcoder-pipeline-architecture.md + knowledge/AVTranscoder/entities/engine-layer-entities.md |
| 水印逻辑修改 | `hitranscoder_impl.cpp`、WaterMarkFilter（av_codec） | knowledge/AVTranscoder/technologies/watermark-and-video-processing.md + knowledge/AVTranscoder/entities/engine-layer-entities.md |
| 音频直通/编码修改 | `hitranscoder_impl.cpp`、AudioEncoderFilter（av_codec） | knowledge/AVTranscoder/entities/engine-layer-entities.md + knowledge/AVTranscoder/technologies/transcoder-pipeline-architecture.md |
| 回调/进度上报修改 | `hitranscoder_callback_looper.cpp`、`transcoder_server.cpp` | knowledge/AVTranscoder/technologies/transcoder-callback-and-progress.md + knowledge/AVTranscoder/entities/ipc-layer-entities.md |
| 错误码/DFX 打点 | `transcoder_server.cpp` | knowledge/AVTranscoder/technologies/transcoder-error-handling-and-dfx.md |
| NAPI/JS API 变更 | `avtranscoder_napi.cpp`、`transcoder_impl.cpp` | knowledge/AVTranscoder/entities/api-layer.md |
| C API 变更 | `native_avtranscoder.cpp`、`transcoder_impl.cpp` | knowledge/AVTranscoder/entities/api-layer.md |
| CJ API 变更 | `cj_avtranscoder.cpp`、`transcoder_impl.cpp` | knowledge/AVTranscoder/entities/api-layer.md |
| 配置/格式支持修改 | `transcoder_impl.cpp`、`hitranscoder_impl.cpp` | knowledge/AVTranscoder/technologies/transcoder-config-and-formats.md + knowledge/AVTranscoder/entities/engine-layer-entities.md |

### AVMetadata 模块（元数据/缩略图）

知识目录：`knowledge/AVMeta/`

```
knowledge/AVMeta/
├── glossary.md                              # 术语表
├── business-context.md                      # 业务背景
├── architecture.md                          # 架构设计及约束
├── coding-standards.md                      # 编码规范
├── entities/
│   ├── api-layer.md                         # API 接入层实体
│   ├── service-layer.md                     # 服务层实体
│   ├── ipc-layer-entities.md                # IPC 层实体
│   ├── engine-layer-entities.md             # 引擎层实体
│   └── engine-factory-and-selection.md      # 引擎工厂与选择
└── technologies/
    ├── metadata-lifecycle.md                # 元数据完整生命周期
    ├── thumbnail-architecture.md            # 缩略图生成架构
    ├── ipc-communication.md                 # IPC 通信与回调机制
    ├── metadata-features.md                 # 元数据提取特性
    ├── error-handling-and-dfx.md            # 错误处理与 DFX 诊断
    ├── pipeline-architecture.md             # 解码流水线架构
    ├── design-patterns.md                   # 设计模式与架构解耦
    ├── media-source-and-protocol.md         # 媒体源与协议
    ├── evolution.md                         # 模块演进记录
    └── flows.md                             # 关键流程详解
```

| 场景 | 先读 | 加载时机 |
|------|------|---------|
| 理解业务术语 | glossary.md | 启动加载 |
| 理解系统定位与外部依赖 | business-context.md | 启动加载 |
| 模块设计 / 引擎开发 / 架构变更 | architecture.md | 按需加载 |
| 编码前必读 | coding-standards.md | 按需加载 |
| API 接入层实体与约束 | entities/api-layer.md | |
| 服务层实体 | entities/service-layer.md | |
| IPC 层实体 | entities/ipc-layer-entities.md | |
| 引擎层实体 | entities/engine-layer-entities.md | |
| 引擎工厂注册与打分选择 | entities/engine-factory-and-selection.md | |
| 元数据完整生命周期 | technologies/metadata-lifecycle.md | |
| 缩略图生成架构 | technologies/thumbnail-architecture.md | |
| IPC 通信与回调机制 | technologies/ipc-communication.md | |
| 元数据提取特性 | technologies/metadata-features.md | |
| 错误处理与 DFX 诊断 | technologies/error-handling-and-dfx.md | |
| 解码流水线架构 | technologies/pipeline-architecture.md | |
| 设计模式与架构解耦 | technologies/design-patterns.md | |
| 媒体源与协议 | technologies/media-source-and-protocol.md | |
| 模块演进记录 | technologies/evolution.md | |
| 关键流程详解 | technologies/flows.md | |

### 路径→文档触发规则

修改以下目录时，必须先阅读对应知识文档：

#### AVPlayer 相关路径

| 修改路径 | 必读文档 | 原因 |
|----------|---------|------|
| frameworks/native/player/ | knowledge/AVPlayer/entities/api-layer.md | API 层实体与约束，状态机调用顺序 |
| frameworks/native/capi/player/ | knowledge/AVPlayer/entities/api-layer.md | C API 封装约束，OH_AVPlayer 回调机制 |
| frameworks/js/napi/ | knowledge/AVPlayer/entities/api-layer.md | NAPI 桥接层调用链 |
| services/services/player/ipc/ | knowledge/AVPlayer/technologies/ipc-communication.md + knowledge/AVPlayer/entities/ipc-layer-entities.md | IPC 序列化约束、回调不可阻塞、Freeze 机制 |
| services/services/player/ | knowledge/AVPlayer/technologies/player-lifecycle.md + knowledge/AVPlayer/entities/service-layer.md | 8 状态状态机、TaskMgr 异步约束、ConfigInfo 原子性 |
| services/services/player/player_mem_manage/ | knowledge/AVPlayer/technologies/memory-and-background.md | 内存回收/恢复流程、前台后台策略 |
| services/engine/histreamer/player/ | knowledge/AVPlayer/technologies/pipeline-architecture.md + knowledge/AVPlayer/entities/engine-layer-entities.md | Pipeline 统一控制约束、Filter 接口契约 |
| services/engine/histreamer/lpp/ | knowledge/AVPlayer/entities/engine-factory-and-selection.md | LPP 引擎实体、HDI 同步机制 |
| services/engine/ | knowledge/AVPlayer/entities/engine-factory-and-selection.md | 引擎工厂注册与打分选择，dlopen 约束 |
| plugins/ | knowledge/AVPlayer/technologies/media-source-and-protocol.md | 插件 Sniff 注册机制、路径安全校验 |

#### AVRecorder 相关路径

| 修改路径 | 必读文档 | 原因 |
|----------|---------|------|
| `frameworks/js/avrecorder/` | `knowledge/AVRecorder/entities/AVRecorder.md` | JS API 兼容性、NAPI 绑定约束 |
| `frameworks/js/avrecorder/avrecorder_napi.h` | `knowledge/AVRecorder/entities/AVRecorderConfig.md` + `knowledge/AVRecorder/entities/RecorderProfiles.md` | AVRecorderConfig/AVRecorderProfile 字段定义、IPC 序列化兼容性 |
| `services/services/recorder/server/` | `knowledge/AVRecorder/entities/RecorderServer.md` | 录制服务状态机（RecStatus）、ConfigInfo 原子性、WatchDog |
| `services/services/recorder/ipc/` | `knowledge/AVRecorder/technologies/IPCLayer.md` | IPC parcel 字段顺序、回调路由、Proxy/Stub 一致性 |
| `services/services/engine_intf/` | `knowledge/AVRecorder/entities/RecorderCallback.md` | IRecorderEngineObs 回调接口、错误/信息上报契约 |
| `services/engine/histreamer/recorder/` | `knowledge/AVRecorder/entities/HiRecorder.md` | 状态机转换（StateId）、Pipeline 构建（BuildPipeline） |
| `services/engine/histreamer/recorder/recorder_utils.h` | `knowledge/AVRecorder/entities/SourceId.md` | SourceId 掩码常量（AUDIO_MASK/VIDEO_MASK/META_MASK）、source type 逻辑 |
| `services/services/recorder/server/media_library_adapter.*` | `knowledge/AVRecorder/entities/RecorderServer.md` | FileGenerationMode、MediaLibrary 文件创建逻辑 |
| `av_codec/services/media_engine/filters/audio_capture_filter.*` | `knowledge/AVRecorder/technologies/AudioVideoCapture.md` | 音频采集 Filter 生命周期、Surface 契约 |
| `av_codec/services/media_engine/filters/video_capture_filter.*` | `knowledge/AVRecorder/technologies/AudioVideoCapture.md` | 视频采集 Filter 生命周期、getInputSurface 时序 |
| `av_codec/services/media_engine/filters/water_mark_filter.*` | `knowledge/AVRecorder/entities/WaterMark.md` + `knowledge/AVRecorder/technologies/WatermarkFusion.md` | 水印渲染、OpenGL shader、硬件/软件水印兼容性 |
| `av_codec/services/media_engine/filters/muxer_filter.*` | `knowledge/AVRecorder/technologies/Muxer.md` | 封装格式、track 添加逻辑、容器写入、跨版本兼容性 |
| `av_codec/services/media_engine/filters/audio_encoder_filter.*` | — | 音频编码 Filter（无独立知识文档，参考 Pipeline.md） |
| `av_codec/services/media_engine/filters/surface_encoder_filter.*` | — | 视频编码 Filter（无独立知识文档，参考 Pipeline.md） |

**AVPlayer 关键词触发规则**：

- 提及 **Seek, SeekAgent, DoSeek, OnSeekDone** → 先读 `knowledge/AVPlayer/technologies/seek-architecture.md`
- 提及 **LPP, LppEngine, LppStreamPlayer, HDI** → 先读 `knowledge/AVPlayer/entities/engine-factory-and-selection.md`
- 提及 **BufferQueue, AVBufferQueue, BufferManager** → 先读 `knowledge/AVPlayer/technologies/av-sync-and-buffer.md`
- 提及 **Freeze, Unfreeze, AppBackground, memory reclaim** → 先读 `knowledge/AVPlayer/technologies/memory-and-background.md`
- 提及 **RecoverConfigInfo, RestoreConfig, PlayerServerMem** → 先读 `knowledge/AVPlayer/technologies/memory-and-background.md`
- 提及 **Pipeline, Filter, HiPlayerImpl, DemuxerFilter, DecoderFilter** → 先读 `knowledge/AVPlayer/technologies/pipeline-architecture.md` 和 `knowledge/AVPlayer/entities/engine-layer-entities.md`
- 提及 **状态机, PlayerState, BaseState, stateCtrlList** → 先读 `knowledge/AVPlayer/technologies/player-lifecycle.md`
- 提及 **IPC, Proxy, Stub, PlayerClient, PlayerServiceStub, PlayerListenerProxy** → 先读 `knowledge/AVPlayer/technologies/ipc-communication.md` 和 `knowledge/AVPlayer/entities/ipc-layer-entities.md`
- 提及 **EngineFactory, Score, dlopen, HstEngineFactory, LppEngineFactory** → 先读 `knowledge/AVPlayer/entities/engine-factory-and-selection.md`
- 提及 **Sniff, SourcePlugin, DemuxerPlugin, CodecPlugin** → 先读 `knowledge/AVPlayer/technologies/media-source-and-protocol.md`

**AVRecorder 关键词触发规则**：

- 提及 **AVRecorder, createAVRecorder, AVRecorderConfig, AVRecorderProfile** → 先读 `knowledge/AVRecorder/entities/AVRecorder.md` 和 `knowledge/AVRecorder/entities/AVRecorderConfig.md`
- 提及 **HiRecorder, HiRecorderImpl, Pipeline, Filter, BuildPipeline** → 先读 `knowledge/AVRecorder/entities/HiRecorder.md` 和 `knowledge/AVRecorder/technologies/Pipeline.md`
- 提及 **Watermark, WaterMarkFilter, SetWatermark, AddWatermark, OpenGL watermark** → 先读 `knowledge/AVRecorder/entities/WaterMark.md` 和 `knowledge/AVRecorder/technologies/WatermarkFusion.md`
- 提及 **Muxer, MuxerFilter, MediaMuxer, OutputFormat, container format** → 先读 `knowledge/AVRecorder/technologies/Muxer.md`
- 提及 **SourceId, AudioSourceType, VideoSourceType, MetaSourceType, DUMMY_SOURCE_ID** → 先读 `knowledge/AVRecorder/entities/SourceId.md`
- 提及 **IPC, Proxy, Stub, RecorderClient, RecorderServer, IStandardRecorderService** → 先读 `knowledge/AVRecorder/technologies/IPCLayer.md`
- 提及 **AudioCapturer, AudioCaptureFilter, VideoCaptureFilter, Surface, getInputSurface** → 先读 `knowledge/AVRecorder/technologies/AudioVideoCapture.md`

#### 其它模块路径

#### AVMeta 相关路径

| 修改路径 | 必读文档 | 原因 |
|----------|---------|------|
| frameworks/native/avmetadatahelper/ | knowledge/AVMeta/entities/api-layer.md | API 层实体与约束，三接口合一，PixelMap 转换 |
| frameworks/native/capi/avmetadatahelper/ | knowledge/AVMeta/entities/api-layer.md | C API 封装约束，OH_AVMetadataExtractor/OH_AVImageGenerator |
| frameworks/js/metadatahelper/ | knowledge/AVMeta/entities/api-layer.md | NAPI 桥接层调用链，AVMetadataExtractorNapi/AVImageGeneratorNapi |
| frameworks/cj/metadatahelper/ | knowledge/AVMeta/entities/api-layer.md | CJ-FFI 桥接层 |
| frameworks/taihe/media/ | knowledge/AVMeta/entities/api-layer.md | Taihe 桥接层 |
| services/services/avmetadatahelper/ipc/ | knowledge/AVMeta/technologies/ipc-communication.md + knowledge/AVMeta/entities/ipc-layer-entities.md | IPC 序列化约束、回调不可阻塞、参数限制 |
| services/services/avmetadatahelper/server/ | knowledge/AVMeta/technologies/metadata-lifecycle.md + knowledge/AVMeta/entities/service-layer.md | 4 状态状态机、TaskQueue 串行化、懒初始化 |
| services/services/avmetadatahelper/client/ | knowledge/AVMeta/entities/ipc-layer-entities.md | IPC 客户端代理，死亡通知 |
| services/engine/histreamer/avmetadatahelper/ | knowledge/AVMeta/technologies/thumbnail-architecture.md + knowledge/AVMeta/entities/engine-layer-entities.md | 缩略图生成、硬软解切换、懒初始化约束 |
| services/engine/histreamer/factory/ | knowledge/AVMeta/entities/engine-factory-and-selection.md | 引擎工厂注册与打分选择，SCENE_AVMETADATA |
| interfaces/inner_api/native/avmetadatahelper.h | knowledge/AVMeta/entities/api-layer.md | InnerAPI 契约定义 |
| interfaces/kits/c/avmetadata_extractor.h | knowledge/AVMeta/entities/api-layer.md | C API 接口定义 |

#### 其它模块路径

### 高频修改场景→源码文件映射

#### AVPlayer 场景

| 修改场景 | 涉及源码文件 | 必读知识文档 |
|----------|------------|------------|
| Seek 逻辑修改 | `hiplayer_impl.cpp`、`seek_agent.cpp`、`pipeline.cpp`、`demuxer_filter.cpp` | knowledge/AVPlayer/technologies/seek-architecture.md + knowledge/AVPlayer/entities/engine-layer-entities.md |
| 状态机调整 | `player_server.cpp`（BaseState 子类） | knowledge/AVPlayer/technologies/player-lifecycle.md + knowledge/AVPlayer/technologies/design-patterns.md |
| IPC 接口增删 | `player_service_stub.cpp`、`player_service_proxy.cpp`、`player_client.cpp`、`player_listener_proxy.cpp` | knowledge/AVPlayer/technologies/ipc-communication.md + knowledge/AVPlayer/entities/ipc-layer-entities.md |
| 引擎注册/选择 | `engine_factory_repo.cpp`、`hst_engine_factory.cpp`、`lpp_engine_factory.cpp` | knowledge/AVPlayer/entities/engine-factory-and-selection.md |
| 内存回收策略 | `player_server_mem.cpp`、`player_mem_manage.cpp` | knowledge/AVPlayer/technologies/memory-and-background.md |
| Pipeline Filter 新增/修改 | 对应 `*_filter.cpp` + `pipeline.cpp` | knowledge/AVPlayer/technologies/pipeline-architecture.md |
| NAPI/JS API 变更 | `avplayer_napi.cpp`、`player_impl.cpp` | knowledge/AVPlayer/entities/api-layer.md |
| C API 变更 | `avplayer.cpp`、`player_object.cpp` | knowledge/AVPlayer/entities/api-layer.md |
| 插件新增（Source/Demuxer/Codec） | 对应 `plugins/*/` 目录 | knowledge/AVPlayer/technologies/media-source-and-protocol.md |
| 音视频同步调整 | `media_sync_manager.cpp`、`audio_sink_plugin.cpp` | knowledge/AVPlayer/technologies/av-sync-and-buffer.md |
| 错误码/DFX 打点 | `player_server.cpp`、`dfx_agent.cpp` | knowledge/AVPlayer/technologies/error-handling-and-dfx.md |

#### AVRecorder 场景

| 修改场景 | 涉及源码文件 | 必读知识文档 |
|----------|------------|------------|
| NAPI/JS API 变更 | `avrecorder_napi.cpp`、`avrecorder_napi.h` | `knowledge/AVRecorder/entities/AVRecorder.md` |
| 状态机调整 | `recorder_server.cpp`（RecStatus） | `knowledge/AVRecorder/entities/RecorderServer.md` |
| IPC 接口增删 | `recorder_service_stub.cpp`、`recorder_service_proxy.cpp`、`recorder_client.cpp` | `knowledge/AVRecorder/technologies/IPCLayer.md` |
| Pipeline 构建/Filter 修改 | `hirecorder_impl.cpp`、对应 `*_filter.cpp` | `knowledge/AVRecorder/entities/HiRecorder.md`、`knowledge/AVRecorder/technologies/Pipeline.md` |
| 水印功能修改 | `water_mark_filter.cpp` | `knowledge/AVRecorder/entities/WaterMark.md`、`knowledge/AVRecorder/technologies/WatermarkFusion.md` |
| 封装格式修改 | `muxer_filter.cpp` | `knowledge/AVRecorder/technologies/Muxer.md` |
| Source ID 逻辑 | `recorder_utils.h` | `knowledge/AVRecorder/entities/SourceId.md` |
| 音视频采集修改 | `audio_capture_filter.cpp`、`video_capture_filter.cpp` | `knowledge/AVRecorder/technologies/AudioVideoCapture.md` |
| 编码器修改 | `audio_encoder_filter.cpp`、`surface_encoder_filter.cpp` | — |
| MediaLibrary 适配 | `media_library_adapter.cpp` | — |
| 录制配置/Profile 修改 | `avrecorder_napi.h`（AVRecorderConfig/AVRecorderProfile） | `knowledge/AVRecorder/entities/AVRecorderConfig.md`、`knowledge/AVRecorder/entities/RecorderProfiles.md` |
| 错误回调修改 | `i_recorder_engine.h`（IRecorderEngineObs） | `knowledge/AVRecorder/entities/RecorderCallback.md` |

#### 其它模块场景

#### AVMeta 场景

| 修改场景 | 涉及源码文件 | 必读知识文档 |
|----------|------------|------------|
| 缩略图/帧抓取逻辑修改 | `av_thumbnail_generator.cpp`、`avmetadatahelper_impl.cpp`(engine) | knowledge/AVMeta/technologies/thumbnail-architecture.md + knowledge/AVMeta/entities/engine-layer-entities.md |
| 状态机调整 | `avmetadatahelper_server.cpp`（ChangeState/状态校验） | knowledge/AVMeta/technologies/metadata-lifecycle.md + knowledge/AVMeta/technologies/design-patterns.md |
| IPC 接口增删 | `avmetadatahelper_service_stub.cpp`、`avmetadatahelper_service_proxy.cpp`、`avmetadatahelper_client.cpp`、`helper_listener_proxy.cpp` | knowledge/AVMeta/technologies/ipc-communication.md + knowledge/AVMeta/entities/ipc-layer-entities.md |
| 引擎注册/选择 | `engine_factory_repo.cpp`、`hst_engine_factory.cpp` | knowledge/AVMeta/entities/engine-factory-and-selection.md |
| 元数据提取逻辑 | `avmetadata_collector.cpp` | knowledge/AVMeta/technologies/metadata-features.md + knowledge/AVMeta/entities/engine-layer-entities.md |
| 硬软解切换 | `av_thumbnail_generator.cpp`（IsSupportHWDecoder/SwitchToSoftWareDecoder） | knowledge/AVMeta/technologies/thumbnail-architecture.md |
| NAPI/JS API 变更 | `avmetadataextractor_napi.cpp`、`avimagegenerator_napi.cpp`、`avmetadatahelper_impl.cpp`(client) | knowledge/AVMeta/entities/api-layer.md |
| C API 变更 | `native_avmetadata_extractor.cpp`、`native_avimage_generator.cpp` | knowledge/AVMeta/entities/api-layer.md |
| 像素图/色彩空间处理 | `avmetadatahelper_impl.cpp`(client)（ProcessPixelMap/CreatePixelMapYuv/ScalePixelMap） | knowledge/AVMeta/technologies/thumbnail-architecture.md + knowledge/AVMeta/entities/api-layer.md |
| 超时/取消逻辑 | `avmetadatahelper_server.cpp`、`av_thumbnail_generator.cpp`、`avmetadatahelper_impl.cpp`(engine) | knowledge/AVMeta/technologies/thumbnail-architecture.md + knowledge/AVMeta/technologies/metadata-lifecycle.md |
| 批量帧抓取 | `avmetadatahelper_server.cpp`（FetchFrameYuvs）、`av_thumbnail_generator.cpp` | knowledge/AVMeta/technologies/thumbnail-architecture.md + knowledge/AVMeta/technologies/ipc-communication.md |
| 帧索引转换 | `avmetadatahelper_impl.cpp`(engine)（TimeAndIndexConversion） | knowledge/AVMeta/technologies/metadata-features.md + knowledge/AVMeta/entities/engine-layer-entities.md |
| 错误码/DFX 打点 | `avmetadatahelper_server.cpp`、`avmetadata_collector.cpp` | knowledge/AVMeta/technologies/error-handling-and-dfx.md |
| 媒体源/协议处理 | `avmetadatahelper_impl.cpp`(engine)（SetSource/InitDemuxer） | knowledge/AVMeta/technologies/media-source-and-protocol.md |

#### 其它模块场景

## 架构概要

### 双进程架构

- **MediaServer（System Ability）**：服务端进程，承载播放器/录制器/转码器实例管理、IPC 请求处理、引擎生命周期管理
- **应用进程**：客户端进程，通过 PlayerClient/RecorderClient 等 IPC 代理端与服务端通信

### 核心处理链路

```
应用 (ArkTS/JS/CangJie/C)
  → Bridge Layer (NAPI/FFI/C API)
  → Native API (PlayerImpl / RecorderImpl)
  → IPC (Binder) → Service Server (PlayerServer / RecorderServer)
  → EngineFactory (打分选择引擎)
  → Engine (HiPlayerImpl / HiRecorderImpl / LppEngine)
  → Pipeline
    ├─ 播放: Demuxer → Decoder → Sink
    └─ 录制: Capture → Encoder → Muxer → File
  → HDI 硬件驱动
```

### 引擎选择机制

4 种场景通过 EngineFactoryRepo::Score() 打分选择最优引擎：

| 场景 | 最优引擎 | 说明 |
|------|---------|------|
| PLAYER | Histreamer | 完整 Pipeline 能力 |
| RECORDER | Histreamer | 录制 Pipeline |
| TRANSCODER | Histreamer | 转码 Pipeline |
| LPP_STREAMER | LPP | 硬件解码/渲染/同步 |

## 项目宪法

1. **IPC 是模块边界**：所有跨进程调用必须通过 IPC Proxy/Stub，严禁共享裸指针或引用。
2. **引擎可替换**：新增引擎必须实现 IEngineFactory 接口并通过 dlopen 注册，严禁在服务层硬编码引擎创建逻辑。
3. **Pipeline 统一控制**：Seek/Stop 等生命周期操作必须通过 Pipeline 统一下发，严禁引擎直接操作特定 Filter。
4. **InnerAPI 是服务契约**：服务层与引擎层通过 InnerAPI 头文件解耦，严禁服务层直接依赖引擎实现细节。
5. **状态机保护**：PlayerServer 所有操作必须经过 8 状态状态机校验，非法操作返回 MSERR_INVALID_STATE。
6. **内存回收可恢复**：所有播放状态必须保存到 RecoverConfigInfo，确保内存回收后可完整恢复。
7. **DFX 可观测**：关键路径必须有 HiSysEvent/HiAppEvent 打点，卡顿/错误必须上报。
8. **第三方许可证合规**：ffmpeg 组件受 LGPL 许可证约束，修改 ffmpeg 封装层（DemuxerPlugin/SourcePlugin）需评估许可证影响；hcodec/fcodec 为厂商闭源库，严禁逆向或绕过 InnerAPI 直接调用厂商接口。

## 播放模块边界约束（AVPlayer）

### 禁止事项

- 禁止绕过 IPC Proxy/Stub 在客户端和服务端进程间共享裸指针或引用。
- 禁止跳过 PlayerServer 8 状态状态机校验直接执行操作；非法状态必须返回 MSERR_INVALID_STATE。
- 禁止在引擎层直接操作特定 Filter（如直接调用 DemuxerFilter::Seek）；生命周期操作必须通过 Pipeline 统一下发。
- 禁止在服务层硬编码引擎创建逻辑；新增引擎必须实现 IEngineFactory 接口并通过 dlopen 注册。
- 禁止移除或修改 RecoverConfigInfo 中保存的播放状态字段，否则内存回收后无法完整恢复。
- 禁止修改 IPC parcel 字段顺序或回调 ID 分配而不验证 Proxy/Stub 一致性。
- 禁止绕过权限检查或 IPC token 验证以通过测试。
- 禁止移除关键路径的 HiSysEvent/HiAppEvent 打点以消除测试输出。
- 禁止未评估 LGPL 许可证影响就修改 ffmpeg 封装层（DemuxerPlugin/SourcePlugin）。
- 禁止逆向或绕过 InnerAPI 直接调用 hcodec/fcodec 厂商闭源接口。
- 禁止在 NAPI/JS API 变更时不验证 `avplayer_napi.cpp` 与 `player_impl.cpp` 调用链一致性。
- 禁止在插件 Sniff 注册机制中引入未经安全校验的文件路径。

### 需先确认

- 修改 `frameworks/native/player/` 或 `frameworks/native/capi/player/` 中公共 API 签名、参数名、错误码前需确认。
- 修改 `IPlayerService` 或 `IPlayerEngine` 接口方法签名前需确认。
- 修改 `services/services/player/ipc/` 中 IPC parcel 字段顺序或回调 ID 分配前需确认。
- 修改 PlayerServer 状态机（8 状态、stateCtrlList）或新增状态前需确认。
- 修改 `EngineFactoryRepo::Score()` 打分逻辑或引擎注册机制前需确认。
- 修改 `player_mem_manage.cpp` 内存回收/恢复策略影响前后台行为前需确认。
- 修改 `media_sync_manager.cpp` 音视频同步算法影响播放体验前需确认。
- 修改 `plugins/` 下插件注册或 Sniff 机制影响媒体源识别前需确认。
- 修改 LPP 引擎 HDI 同步调用时序影响硬件解码/渲染前需确认。
- 修改 `RecoverConfigInfo` 序列化字段影响跨版本恢复兼容性前需确认。

### 架构不变量

- **IPC 是模块边界**：`PlayerClient` ↔ `PlayerServer` 通信必须通过 IPC Proxy/Stub。
- **Pipeline 是引擎核心**：所有播放数据流必须通过 Filter Pipeline；禁止 Pipeline 框架外的直接 Filter-to-Filter 指针调用。
- **状态机是权威的**：PlayerServer 8 状态状态机校验必须覆盖所有操作入口。
- **引擎可替换**：引擎选择通过 EngineFactoryRepo 打分，服务层不可依赖特定引擎实现。
- **依赖方向**：NAPI → Service → Engine → MediaEngine Filters → Plugins；不可逆向。

## 播放模块 DFX 约束

- 所有播放错误路径在返回错误码前必须调用 `HiLog` 并带模块标签。
- 播放失败（解码失败、Pipeline 错误、资源不足）必须上报 `HiSysEvent` fault 事件。
- 卡顿/首帧耗时/Seek 耗时等关键体验指标必须有 HiAppEvent 打点。
- 禁止移除或抑制 `MEDIA_LOG_I/W/E` 日志调用以消除测试输出。
- `XCollie` 看门狗不可禁用；它防止播放会话挂起。

## 播放模块常见 Agent 失败模式

- Agent 调用 `Play` 前未调用 `Prepare` → MSERR_INVALID_STATE。调用生命周期方法前必须检查状态。
- Agent 直接操作 Filter 而非通过 Pipeline → 状态不一致。所有生命周期操作必须通过 Pipeline 统一下发。
- Agent 修改状态机但忘记同步 NAPI、Server、Engine 三层 → 状态机不一致。
- Agent 在内存回收回调中尝试异步操作 → 回收流程必须在同步上下文中完成。
- Agent 新增引擎但未注册 IEngineFactory → EngineFactoryRepo 找不到引擎。必须通过 dlopen 注册。
- Agent 修改 IPC parcel 字段但只改 Proxy 或 Stub 一侧 → IPC 不匹配。必须同时修改两侧。

## 播放模块验证

### 最低检查

- 构建：`./build.sh --product-name <product-name> --build-target av_player --ccache`
- 单元测试：`./test.sh av_player_unittest`
- Lint：`./tools/lint_changed.sh <changed-files>`（如可用）

### 任务特定检查

| 变更类型 | 附加检查 |
|---------|---------|
| NAPI/JS API 变更 | 验证 `avplayer_napi.cpp` 与 `player_impl.cpp` 调用链一致；验证状态机调用顺序 |
| C API 变更 | 验证 `avplayer.cpp` 与 `player_object.cpp` 回调机制；验证 OH_AVPlayer 兼容性 |
| IPC parcel 变更 | 验证 Proxy 和 Stub 字段顺序一致；验证回调 ID 不变 |
| 状态机变更 | 验证 8 状态转换覆盖所有操作入口；验证非法状态返回 MSERR_INVALID_STATE |
| 引擎注册/选择 | 验证 EngineFactoryRepo 打分逻辑；验证 dlopen 加载/卸载无泄漏 |
| Pipeline Filter 变更 | 验证 Filter 生命周期（Init→Prepare→Start→Stop→Release）；验证上下游链接正确 |
| 内存回收变更 | 验证 RecoverConfigInfo 完整性；验证前后台切换恢复流程 |
| Seek 变更 | 验证 Seek 精度和时序；验证 SeekAgent 与 Pipeline 协作 |
| 音视频同步变更 | 验证 AVSync 时钟基准；验证缓冲区水位阈值 |
| 插件变更 | 验证 Sniff 注册机制；验证路径安全校验 |
| DFX 打点变更 | 验证 HiSysEvent/HiAppEvent 事件字段完整；验证 XCollie 看门狗未禁用 |

### 完成定义

完成意味着：(1) 构建成功，(2) 相关单元测试通过，(3) lint 无新增警告，(4) 任务特定兼容性/安全检查通过，(5) 无资源泄漏（Player 实例、Surface、fd 已释放）。

### 最终响应要求

最终响应必须列出：(1) 变更文件，(2) 运行的检查及结果，(3) 未解决的风险或无法验证的内容。

### 验证降级

若构建或测试无法运行，报告：(1) 哪些验证步骤无法运行，(2) 原因，(3) 剩余未验证风险，(4) 评审者应执行的手动验证。

## 录制模块边界约束（AVRecorder）

### 禁止事项

- 禁止绕过 IPC Proxy/Stub 在客户端和服务端进程间共享裸指针或引用。
- 禁止跳过状态机检查（`CheckStateMachine`、`RecStatus`）强制执行操作。
- 禁止未在 `FilterFactory` 注册并更新 `HiRecorderImpl::BuildPipeline` 的情况下新增 Filter 类型。
- 禁止修改 `AVRecorderState` 或 `stateCtrlList` 时未验证 NAPI、Server、Engine 三层状态转换一致性。
- 禁止绕过权限检查（MICROPHONE、CAMERA）或 IPC token 验证以通过测试。
- 禁止硬编码编码器名称或 codec MIME 类型；应查询 `CodecCapabilityAdapter`。
- 禁止调用 `Release` 后继续使用 `RecorderClient` 或 `RecorderServer` 实例。
- 禁止直接编辑生成或自动注册的 Filter 绑定；应更新源码并重新构建。
- 禁止未进行跨版本测试就修改输出文件格式兼容性（MP4/M4A/AAC track 结构、udta box 布局）；现有播放客户端可能 break。
- 禁止移除或重排 `ConfigInfo`（RecorderServer）或 `AVRecorderConfig`（NAPI）中通过 IPC 序列化的字段；这会破坏 wire 兼容性。
- 禁止未经许可证审查和审批引入第三方依赖；录制服务运行在系统进程中，有严格的许可证要求。
- 禁止修改 `SaveDocumentSyncCallback` 关闭处理逻辑时未验证强制停止时录制数据完整性。

### 需先确认

- 修改 `frameworks/js/avrecorder/` 中公共 JS API 签名、参数名、错误码或状态机语义前需确认。
- 修改 `IRecorderService` 或 `IRecorderEngine` 接口方法签名前需确认。
- 修改 `services/services/recorder/ipc/` 中 IPC parcel 字段顺序或回调 ID 分配前需确认。
- 修改 `recorder_utils.h` 中 `SourceId` 掩码常量（`AUDIO_MASK`、`VIDEO_MASK`、`META_MASK`）前需确认。
- 修改 `WaterMarkFilter` OpenGL shader 代码影响水印渲染输出前需确认。
- 修改 `MuxerFilter` 格式表或 track 添加逻辑影响输出文件兼容性前需确认。
- 修改 `MAX_WATERMARK_NUMBER`、`MAX_WATERMARK_SIZE` 或水印位置校验前需确认。
- 修改录制服务 SA ID 或进程分配前需确认。
- 修改持久化录制配置默认值（如 `AVRECORDER_DEFAULT_AUDIO_BIT_RATE`、`AVRECORDER_DEFAULT_FRAME_RATE`）影响输出文件特性前需确认。
- 修改 `FileGenerationMode` 行为或 `MediaLibraryAdapter` 文件创建逻辑影响录制资源在媒体相册中的展示前需确认。

### 架构不变量

- **IPC 是模块边界**：`RecorderClient` ↔ `RecorderServer` 通信必须通过 IPC Proxy/Stub。
- **Pipeline 是引擎核心**：所有录制数据流必须通过 Filter Pipeline；禁止 Pipeline 框架外的直接 Filter-to-Filter 指针调用。
- **状态机是权威的**：`stateCtrlList`（NAPI）、`RecStatus`（Server）、`StateId`（Engine）必须保持一致。
- **Source 必须先于 Format**：`SetVideoSource`/`SetAudioSource`/`SetMetaSource` 必须在 `SetOutputFormat` 之前调用。
- **依赖方向**：NAPI → Service → Engine → MediaEngine Filters；不可逆向。

## 录制模块 DFX 约束

- 所有录制错误路径在返回错误码前必须调用 `HiLog` 并带模块标签。
- 录制失败（编码失败、文件写入失败、Pipeline 错误）必须上报 `HiSysEvent` fault 事件。
- `RecorderServer` 中 `StatisticalEventInfo` 必须在录制完成或失败时发送 DFX 事件前填充。
- 禁止移除或抑制 Filter 中的 `MEDIA_LOG_I/W/E` 日志调用以消除测试输出。
- `RecorderServer` 中 WatchDog 不可禁用；它防止录制会话挂起。

## 录制模块常见 Agent 失败模式

- Agent 调用 `Start` 前未调用 `Prepare` → MSERR_INVALID_OPERATION。调用生命周期方法前必须检查状态。
- Agent 在 `Prepare` 前调用 `GetInputSurface` → 返回 null surface。Surface 仅在 Prepare 后可用。
- Agent 混用 `SetWatermark`（硬件）和 `AddWatermark`（软件）未检查 `IsWatermarkSupported` → 在无硬件水印能力的设备上可能报 unsupported。
- Agent 在 `Stop` 后忘记调用 `Release` → Surface 和 fd 泄漏。测试 teardown 中必须 Stop 后跟 Release。
- Agent 添加超过 5 个水印 → MSERR_INVALID_OPERATION。添加前检查 `watermarkCount_`。
- Agent 在一层修改 `stateCtrlList` 但忘记另外两层 → 状态机不一致。

## 录制模块验证

### 最低检查

- 构建：`./build.sh --product-name <product-name> --build-target av_recorder --ccache`
- 单元测试：`./test.sh av_recorder_unittest`
- Lint：`./tools/lint_changed.sh <changed-files>`（如可用）

### 任务特定检查

| 变更类型 | 附加检查 |
|---------|---------|
| NAPI API 变更 | 运行 JS API 兼容性检查；验证 `stateCtrlList` 与 Server `RecStatus` 和 Engine `StateId` 一致 |
| IPC parcel 变更 | 验证 Proxy 和 Stub 字段顺序一致；验证回调 ID 不变 |
| Filter 变更 | 验证 Filter 生命周期（Init→Prepare→Start→Stop→Release）；验证与上游/下游的 AVBufferQueue 契约 |
| 水印变更 | 验证 GPU 上的软件水印渲染输出；验证硬件水印编码输出；测试最大水印数量和尺寸边界 |
| 状态机变更 | 验证三层状态转换表一致性 |
| Config/Profile 变更 | 验证 `AVRecorderConfig` 解析 round-trip（JS→NAPI→Server→Engine） |

### 完成定义

完成意味着：(1) 构建成功，(2) 相关单元测试通过，(3) lint 无新增警告，(4) 任务特定兼容性/安全检查通过，(5) 无资源泄漏（Surface/fd/AudioCapturer 已释放）。

### 最终响应要求

最终响应必须列出：(1) 变更文件，(2) 运行的检查及结果，(3) 未解决的风险或无法验证的内容。

### 验证降级

若构建或测试无法运行，报告：(1) 哪些验证步骤无法运行，(2) 原因，(3) 剩余未验证风险，(4) 评审者应执行的手动验证。

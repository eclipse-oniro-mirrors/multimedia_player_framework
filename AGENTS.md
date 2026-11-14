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

项目知识按模块存放在 `docs/knowledge/` 目录下，每个模块独立子目录：

```
docs/knowledge/
├── AVPlayer/          # 播放器模块（已有）
├── AVRecorder/        # 录制模块（已有）
├── AVScreenCapture/   # 屏幕录制模块（已有）
├── AVTranscoder/      # 转码模块（待建设）
├── AVMeta/            # 元数据/缩略图模块（已有）
└── ...                # 其它模块按需扩展
```

### 加载规范

- **启动时加载**：当前模块的 `glossary.md`（术语表）和 `business-context.md`（业务背景）
- **按需加载**：当前模块的 `architecture.md`（架构设计及约束）、`coding-standards.md`（编码规范）

### 术语查询流程

遇到不了解的术语词汇时：

1. 先确定当前模块：按任务提及的源码路径（查「路径→文档触发规则」）→ 模块标识词（AVPlayer/AVRecorder/AVScreenCapture/AVTranscoder/AVMeta，播放/录制/录屏/转码/元数据）顺序判定；仍无法判定时向用户确认，不得凭跨模块泛化词（IPC/状态机/Pipeline/DFX 等共用语）猜测路由
2. 在当前模块的 **glossary.md** 中查询该术语
3. 若 glossary 提供了「详见/完整信息指向」链接，按需从当前模块的 **entities/、technologies/** 目录加载术语的详细介绍
4. 若当前模块无该术语，查阅对应技术文档或「知识索引」场景表

### 编辑前声明流程

编辑代码前，必须先声明以下信息：

1. **所属模块**：AVPlayer / AVScreenCapture / AVRecorder / AVTranscoder / AVMetadata / 跨模块
2. **任务类别**：API 变更 / 引擎开发 / IPC 修改 / Pipeline 调整 / 内存管理 / DFX 增强 / Bug 修复 / 其它
3. **已读知识文档**：列出已阅读的对应模块 `docs/knowledge/<module>/` 下的相关文档
4. **发现的约束**：从已读文档中提取适用于本次修改的约束规则（引用项目宪法编号或编码铁律编号）
5. **需先确认项**：核对 `docs/knowledge/<module>/architecture.md`「需先确认」清单（AVPlayer 见本文播放模块约束章节；无该清单的模块填"无"），触及清单项时先与模块 Owner 确认再开始编辑

未完成声明前，不得开始编辑代码。

## 知识索引

### AVPlayer 模块（播放器）

知识目录：`docs/knowledge/AVPlayer/`

```
docs/knowledge/AVPlayer/
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

### AVScreenCapture 模块（屏幕录制）

知识目录：`docs/knowledge/AVScreenCapture/`

> 本模块采用渐进式加载：主文档仅保留本索引与路径/关键词触发规则，边界约束、架构不变量、编码铁律、常见失败模式、验证检查均按下表加载对应文档；高频修改场景的源码文件映射已下沉至各实体/技术文档的「源码定位」小节。

```
docs/knowledge/AVScreenCapture/
├── glossary.md                              # 术语表
├── business-context.md                      # 业务背景
├── architecture.md                          # 架构设计及约束
├── coding-standards.md                      # 编码规范
├── entities/
│   ├── api-layer.md                         # API 接入层实体
│   ├── service-layer.md                     # 服务层实体
│   ├── ipc-layer-entities.md                # IPC 层实体
│   ├── capture-implementation.md            # 采集实现实体
│   └── monitor-and-controller.md            # Monitor 与 Controller 实体
└── technologies/
    ├── capture-lifecycle.md                 # 录屏完整生命周期
    ├── ipc-communication.md                 # IPC 通信与回调机制
    ├── privacy-and-permission.md            # 隐私保护与权限机制
    ├── capture-features.md                  # 录制控制特性
    ├── av-sync-and-buffer.md                # 音视频同步与缓冲区管理
    ├── error-handling-and-dfx.md            # 错误处理与 DFX 诊断
    ├── design-patterns.md                   # 设计模式与架构解耦
    ├── flows.md                             # 关键流程详解
    └── evolution.md                         # 模块演进记录
```

| 场景 | 先读 | 加载时机 |
|------|------|---------|
| 理解业务术语 | glossary.md | 启动加载 |
| 理解系统定位与外部依赖 | business-context.md | 启动加载 |
| 模块设计 / 架构变更 | architecture.md | 按需加载 |
| 编码前必读 | coding-standards.md | 按需加载 |
| API 接入层实体与约束 | entities/api-layer.md | 按需加载 |
| 服务层实体与状态机 | entities/service-layer.md | 按需加载 |
| IPC 层实体与序列化约束 | entities/ipc-layer-entities.md | 按需加载 |
| 采集实现实体（虚拟屏幕/音频采集/混音） | entities/capture-implementation.md | 按需加载 |
| Monitor 与 Controller 实体 | entities/monitor-and-controller.md | 按需加载 |
| 录屏完整生命周期 | technologies/capture-lifecycle.md | 按需加载 |
| IPC 通信与回调机制 | technologies/ipc-communication.md | 按需加载 |
| 隐私保护与权限机制 | technologies/privacy-and-permission.md | 按需加载 |
| 录制控制特性 | technologies/capture-features.md | 按需加载 |
| 音视频同步与缓冲区管理 | technologies/av-sync-and-buffer.md | 按需加载 |
| 错误处理与 DFX 诊断 | technologies/error-handling-and-dfx.md | 按需加载 |
| 设计模式与架构解耦 | technologies/design-patterns.md | 按需加载 |
| 关键流程详解 | technologies/flows.md | 按需加载 |
| 模块演进记录 | technologies/evolution.md | 按需加载 |

### AVRecorder 模块（录制）

知识目录：`docs/knowledge/AVRecorder/`

> 本模块采用渐进式加载：主文档仅保留本索引与路径/关键词触发规则，边界约束、架构不变量、需先确认清单、DFX 约束、常见失败模式集中在 `architecture.md` 与 `coding-standards.md`，验证检查集中在 `architecture.md`「验证」节；高频修改场景的源码文件映射已下沉至各实体/技术文档的「代码与符号 / 代码关联」小节。

```
docs/knowledge/AVRecorder/
├── glossary.md                              # 术语表
├── business-context.md                      # 业务背景
├── architecture.md                          # 架构设计及约束
├── coding-standards.md                      # 编码规范
├── entities/
│   ├── av-recorder.md                        # AVRecorder 实体（JS/ArkTS API 行为、NAPI 绑定）
│   ├── recorder-server.md                    # 录制服务层实体（状态机、配置）
│   ├── hi-recorder.md                        # HiRecorder 引擎实体（Pipeline 构建、Filter 接线）
│   ├── av-recorder-config.md                  # 录制配置实体（AVRecorderConfig/AVRecorderProfile）
│   ├── recorder-profiles.md                  # 录制 Profile 实体
│   ├── source-id.md                          # Source ID 实体（AUDIO_MASK/VIDEO_MASK/META_MASK）
│   ├── water-mark.md                         # 水印实体（硬件/软件水印）
│   └── recorder-callback.md                  # 录制回调实体（IRecorderEngineObs）
└── technologies/
    ├── ipc-layer.md                          # IPC 层技术（Proxy/Stub、回调路由）
    ├── pipeline.md                          # Pipeline 架构技术（Filter 生命周期、AVBufferQueue 契约）
    ├── audio-video-capture.md                 # 音视频采集技术（AudioCaptureFilter/VideoCaptureFilter/Surface）
    ├── watermark-fusion.md                   # 水印融合技术（OpenGL shader、硬件/软件水印）
    └── muxer.md                             # 封装技术（MuxerFilter、输出格式、容器写入）
```

| 场景 | 起始路径 | 辅助阅读 |
|------|---------|---------|
| JS/ArkTS API 行为或 NAPI 绑定 | `frameworks/js/avrecorder/` | `docs/knowledge/AVRecorder/entities/av-recorder.md` |
| 服务层状态机或配置 | `services/services/recorder/server/` | `docs/knowledge/AVRecorder/entities/recorder-server.md` |
| IPC 客户端/服务端或回调 | `services/services/recorder/ipc/` | `docs/knowledge/AVRecorder/technologies/ipc-layer.md` |
| Pipeline 构建或 Filter 接线 | `services/engine/histreamer/recorder/` | `docs/knowledge/AVRecorder/entities/hi-recorder.md`, `docs/knowledge/AVRecorder/technologies/pipeline.md` |
| 音频/视频采集 Filter | `av_codec/services/media_engine/filters/audio_capture_filter.*`, `video_capture_filter.*` | `docs/knowledge/AVRecorder/technologies/audio-video-capture.md` |
| 音频/视频编码 Filter | `av_codec/services/media_engine/filters/audio_encoder_filter.*`, `surface_encoder_filter.*` | — |
| 水印叠加 | `av_codec/services/media_engine/filters/water_mark_filter.*` | `docs/knowledge/AVRecorder/entities/water-mark.md`, `docs/knowledge/AVRecorder/technologies/watermark-fusion.md` |
| 封装/容器写入 | `av_codec/services/media_engine/filters/muxer_filter.*` | `docs/knowledge/AVRecorder/technologies/muxer.md` |
| Source ID 或 source type 逻辑 | `services/engine/histreamer/recorder/recorder_utils.h` | `docs/knowledge/AVRecorder/entities/source-id.md` |
| 录制配置或 Profile | `frameworks/js/avrecorder/avrecorder_napi.h`（AVRecorderConfig/AVRecorderProfile） | `docs/knowledge/AVRecorder/entities/av-recorder-config.md`, `docs/knowledge/AVRecorder/entities/recorder-profiles.md` |
| 错误回调或信息上报 | `services/services/engine_intf/i_recorder_engine.h`（IRecorderEngineObs） | `docs/knowledge/AVRecorder/entities/recorder-callback.md` |
| MediaLibrary 适配器（自动创建文件） | `services/services/recorder/server/media_library_adapter.*` | — |
| 测试 | `test/unittest/` | — |

### AVTranscoder 模块（转码）

知识目录：`docs/knowledge/AVTranscoder/`

```
docs/knowledge/AVTranscoder/
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
| frameworks/native/transcoder/ | docs/knowledge/AVTranscoder/entities/api-layer.md | API 层实体与约束，TransCoder/TransCoderImpl InnerAPI 实现 |
| frameworks/native/capi/avtranscoder/ | docs/knowledge/AVTranscoder/entities/api-layer.md | C API 封装约束，OH_AVTranscoder 回调机制、配置结构 |
| frameworks/js/avtranscoder/ | docs/knowledge/AVTranscoder/entities/api-layer.md | NAPI 桥接层调用链，AVTransCoderNapi/AVTransCoderCallback |
| frameworks/cj/avtranscoder/ | docs/knowledge/AVTranscoder/entities/api-layer.md | CJ-FFI 桥接层，CJAVTranscoder/CJAVTranscoderCallback |
| frameworks/taihe/media/ | docs/knowledge/AVTranscoder/entities/api-layer.md | Taihe 桥接层，AVTranscoderImpl async/promise |
| interfaces/inner_api/native/transcoder.h | docs/knowledge/AVTranscoder/entities/api-layer.md | InnerAPI 契约定义，TransCoder/TransCoderCallback/TransCoderFactory |
| interfaces/kits/c/avtranscoder.h | docs/knowledge/AVTranscoder/entities/api-layer.md | C API 公共接口定义，OH_AVTranscoder_State 枚举 |
| services/services/transcoder/server/ | docs/knowledge/AVTranscoder/entities/service-layer.md + docs/knowledge/AVTranscoder/technologies/transcoder-lifecycle.md | 6 状态状态机、TaskQueue 同步队列、ConfigInfo |
| services/services/transcoder/client/ | docs/knowledge/AVTranscoder/entities/ipc-layer-entities.md | IPC 客户端代理，MonitorClientObject 心跳 |
| services/services/transcoder/ipc/ | docs/knowledge/AVTranscoder/technologies/transcoder-ipc-communication.md + docs/knowledge/AVTranscoder/entities/ipc-layer-entities.md | IPC 序列化约束、FD 传递、Monitor 心跳、Stub 销毁 |
| services/engine/histreamer/transcoder/ | docs/knowledge/AVTranscoder/technologies/transcoder-pipeline-architecture.md + docs/knowledge/AVTranscoder/entities/engine-layer-entities.md | Pipeline 动态搭建、VideoProcessMode、Surface 级联、HiTransCoderCallbackLooper |

#### AVTranscoder 高频修改场景→源码文件映射

| 修改场景 | 涉及源码文件 | 必读知识文档 |
|----------|------------|------------|
| 状态机调整 | `transcoder_server.cpp` | docs/knowledge/AVTranscoder/technologies/transcoder-state-machine.md + docs/knowledge/AVTranscoder/entities/service-layer.md |
| IPC 接口增删 | `transcoder_service_stub.cpp`、`transcoder_service_proxy.cpp`、`transcoder_listener_proxy.cpp`、`transcoder_listener_stub.cpp` | docs/knowledge/AVTranscoder/technologies/transcoder-ipc-communication.md + docs/knowledge/AVTranscoder/entities/ipc-layer-entities.md |
| 引擎注册/选择 | `engine_factory_repo.cpp`、`hst_engine_factory.cpp` | docs/knowledge/AVTranscoder/entities/engine-factory-and-selection.md |
| Pipeline Filter 新增/修改 | 对应 `*_filter.cpp` + `hi_transcoder_pipeline.cpp`（av_codec） | docs/knowledge/AVTranscoder/technologies/transcoder-pipeline-architecture.md + docs/knowledge/AVTranscoder/entities/engine-layer-entities.md |
| 水印逻辑修改 | `hitranscoder_impl.cpp`、WaterMarkFilter（av_codec） | docs/knowledge/AVTranscoder/technologies/watermark-and-video-processing.md + docs/knowledge/AVTranscoder/entities/engine-layer-entities.md |
| 音频直通/编码修改 | `hitranscoder_impl.cpp`、AudioEncoderFilter（av_codec） | docs/knowledge/AVTranscoder/entities/engine-layer-entities.md + docs/knowledge/AVTranscoder/technologies/transcoder-pipeline-architecture.md |
| 回调/进度上报修改 | `hitranscoder_callback_looper.cpp`、`transcoder_server.cpp` | docs/knowledge/AVTranscoder/technologies/transcoder-callback-and-progress.md + docs/knowledge/AVTranscoder/entities/ipc-layer-entities.md |
| 错误码/DFX 打点 | `transcoder_server.cpp` | docs/knowledge/AVTranscoder/technologies/transcoder-error-handling-and-dfx.md |
| NAPI/JS API 变更 | `avtranscoder_napi.cpp`、`transcoder_impl.cpp` | docs/knowledge/AVTranscoder/entities/api-layer.md |
| C API 变更 | `native_avtranscoder.cpp`、`transcoder_impl.cpp` | docs/knowledge/AVTranscoder/entities/api-layer.md |
| CJ API 变更 | `cj_avtranscoder.cpp`、`transcoder_impl.cpp` | docs/knowledge/AVTranscoder/entities/api-layer.md |
| 配置/格式支持修改 | `transcoder_impl.cpp`、`hitranscoder_impl.cpp` | docs/knowledge/AVTranscoder/technologies/transcoder-config-and-formats.md + docs/knowledge/AVTranscoder/entities/engine-layer-entities.md |

### AVMetadata 模块（元数据/缩略图）

知识目录：`docs/knowledge/AVMeta/`

```
docs/knowledge/AVMeta/
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
| frameworks/native/player/ | docs/knowledge/AVPlayer/entities/api-layer.md | API 层实体与约束，状态机调用顺序 |
| frameworks/native/capi/player/ | docs/knowledge/AVPlayer/entities/api-layer.md | C API 封装约束，OH_AVPlayer 回调机制 |
| frameworks/js/napi/ | docs/knowledge/AVPlayer/entities/api-layer.md | NAPI 桥接层调用链 |
| services/services/player/ipc/ | docs/knowledge/AVPlayer/technologies/ipc-communication.md + docs/knowledge/AVPlayer/entities/ipc-layer-entities.md | IPC 序列化约束、回调不可阻塞、Freeze 机制 |
| services/services/player/ | docs/knowledge/AVPlayer/technologies/player-lifecycle.md + docs/knowledge/AVPlayer/entities/service-layer.md | 8 状态状态机、TaskMgr 异步约束、ConfigInfo 原子性 |
| services/services/player/player_mem_manage/ | docs/knowledge/AVPlayer/technologies/memory-and-background.md | 内存回收/恢复流程、前台后台策略 |
| services/engine/histreamer/player/ | docs/knowledge/AVPlayer/technologies/pipeline-architecture.md + docs/knowledge/AVPlayer/entities/engine-layer-entities.md | Pipeline 统一控制约束、Filter 接口契约 |
| services/engine/histreamer/lpp/ | docs/knowledge/AVPlayer/entities/engine-factory-and-selection.md | LPP 引擎实体、HDI 同步机制 |
| services/engine/ | docs/knowledge/AVPlayer/entities/engine-factory-and-selection.md | 引擎工厂注册与打分选择，dlopen 约束 |
| plugins/ | docs/knowledge/AVPlayer/technologies/media-source-and-protocol.md | 插件 Sniff 注册机制、路径安全校验 |

#### AVRecorder 相关路径

| 修改路径 | 必读文档 | 原因 |
|----------|---------|------|
| `frameworks/js/avrecorder/` | `docs/knowledge/AVRecorder/entities/av-recorder.md` | JS API 兼容性、NAPI 绑定约束 |
| `frameworks/js/avrecorder/avrecorder_napi.h` | `docs/knowledge/AVRecorder/entities/av-recorder-config.md` + `docs/knowledge/AVRecorder/entities/recorder-profiles.md` | AVRecorderConfig/AVRecorderProfile 字段定义、IPC 序列化兼容性 |
| `services/services/recorder/server/` | `docs/knowledge/AVRecorder/entities/recorder-server.md` | 录制服务状态机（RecStatus）、ConfigInfo 原子性、WatchDog |
| `services/services/recorder/ipc/` | `docs/knowledge/AVRecorder/technologies/ipc-layer.md` | IPC parcel 字段顺序、回调路由、Proxy/Stub 一致性 |
| `services/services/engine_intf/` | `docs/knowledge/AVRecorder/entities/recorder-callback.md` | IRecorderEngineObs 回调接口、错误/信息上报契约 |
| `services/engine/histreamer/recorder/` | `docs/knowledge/AVRecorder/entities/hi-recorder.md` | 状态机转换（StateId）、Pipeline 构建（BuildPipeline） |
| `services/engine/histreamer/recorder/recorder_utils.h` | `docs/knowledge/AVRecorder/entities/source-id.md` | SourceId 掩码常量（AUDIO_MASK/VIDEO_MASK/META_MASK）、source type 逻辑 |
| `services/services/recorder/server/media_library_adapter.*` | `docs/knowledge/AVRecorder/entities/recorder-server.md` | FileGenerationMode、MediaLibrary 文件创建逻辑 |
| `av_codec/services/media_engine/filters/audio_capture_filter.*` | `docs/knowledge/AVRecorder/technologies/audio-video-capture.md` | 音频采集 Filter 生命周期、Surface 契约 |
| `av_codec/services/media_engine/filters/video_capture_filter.*` | `docs/knowledge/AVRecorder/technologies/audio-video-capture.md` | 视频采集 Filter 生命周期、getInputSurface 时序 |
| `av_codec/services/media_engine/filters/water_mark_filter.*` | `docs/knowledge/AVRecorder/entities/water-mark.md` + `docs/knowledge/AVRecorder/technologies/watermark-fusion.md` | 水印渲染、OpenGL shader、硬件/软件水印兼容性 |
| `av_codec/services/media_engine/filters/muxer_filter.*` | `docs/knowledge/AVRecorder/technologies/muxer.md` | 封装格式、track 添加逻辑、容器写入、跨版本兼容性 |
| `av_codec/services/media_engine/filters/audio_encoder_filter.*` | — | 音频编码 Filter（无独立知识文档，参考 pipeline.md） |
| `av_codec/services/media_engine/filters/surface_encoder_filter.*` | — | 视频编码 Filter（无独立知识文档，参考 pipeline.md） |

**AVPlayer 关键词触发规则**：

- 提及 **Seek, SeekAgent, DoSeek, OnSeekDone** → 先读 `docs/knowledge/AVPlayer/technologies/seek-architecture.md`
- 提及 **LPP, LppEngine, LppStreamPlayer, HDI** → 先读 `docs/knowledge/AVPlayer/entities/engine-factory-and-selection.md`
- 提及 **BufferQueue, AVBufferQueue, BufferManager** → 先读 `docs/knowledge/AVPlayer/technologies/av-sync-and-buffer.md`
- 提及 **Freeze, Unfreeze, AppBackground, memory reclaim** → 先读 `docs/knowledge/AVPlayer/technologies/memory-and-background.md`
- 提及 **RecoverConfigInfo, RestoreConfig, PlayerServerMem** → 先读 `docs/knowledge/AVPlayer/technologies/memory-and-background.md`
- 提及 **Pipeline, Filter, HiPlayerImpl, DemuxerFilter, DecoderFilter** → 先读 `docs/knowledge/AVPlayer/technologies/pipeline-architecture.md` 和 `docs/knowledge/AVPlayer/entities/engine-layer-entities.md`
- 提及 **状态机, PlayerState, BaseState, stateCtrlList** → 先读 `docs/knowledge/AVPlayer/technologies/player-lifecycle.md`
- 提及 **IPC, Proxy, Stub, PlayerClient, PlayerServiceStub, PlayerListenerProxy** → 先读 `docs/knowledge/AVPlayer/technologies/ipc-communication.md` 和 `docs/knowledge/AVPlayer/entities/ipc-layer-entities.md`
- 提及 **EngineFactory, Score, dlopen, HstEngineFactory, LppEngineFactory** → 先读 `docs/knowledge/AVPlayer/entities/engine-factory-and-selection.md`
- 提及 **Sniff, SourcePlugin, DemuxerPlugin, CodecPlugin** → 先读 `docs/knowledge/AVPlayer/technologies/media-source-and-protocol.md`

**AVRecorder 关键词触发规则**：

- 提及 **AVRecorder, createAVRecorder, RecorderServer, RecorderClient, HiRecorder, 录制** 或本模块领域术语（AVRecorderConfig/AVRecorderProfile、Pipeline、Watermark、Muxer、SourceId、IPC 消息码、采集 Filter、getInputSurface 等）→ 先读 `docs/knowledge/AVRecorder/glossary.md`，按术语「详见」链接直达对应实体/技术文档（模块上下文确定时 glossary 已随「加载规范」启动加载）；术语未收录时查「知识索引 → AVRecorder」场景表

#### AVScreenCapture 相关路径

| 修改路径 | 必读文档 | 原因 |
|----------|---------|------|
| frameworks/native/screen_capture/ | docs/knowledge/AVScreenCapture/entities/api-layer.md | Native API 层实体与约束，ScreenCaptureImpl 转发逻辑 |
| frameworks/native/capi/screencapture/ | docs/knowledge/AVScreenCapture/entities/api-layer.md | C API 封装约束，OH_AVScreenCapture 回调机制，新旧回调适配 |
| frameworks/js/avscreen_capture/ | docs/knowledge/AVScreenCapture/entities/api-layer.md | NAPI 桥接层调用链，TaskQueue 异步调度 |
| frameworks/js/screencapturemonitor/ | docs/knowledge/AVScreenCapture/entities/monitor-and-controller.md | Monitor NAPI 桥接，监听器注册 |
| frameworks/cj/avscreen_capture/ | docs/knowledge/AVScreenCapture/entities/api-layer.md | 仓颉 FFI 桥接层 |
| services/services/screen_capture/ipc/ | docs/knowledge/AVScreenCapture/technologies/ipc-communication.md + docs/knowledge/AVScreenCapture/entities/ipc-layer-entities.md | IPC 序列化约束、回调不可阻塞、41 个消息码 |
| services/services/screen_capture/server/ | docs/knowledge/AVScreenCapture/technologies/capture-lifecycle.md + docs/knowledge/AVScreenCapture/entities/service-layer.md | 7 状态能力位图状态机、ScreenCaptureServer 核心逻辑 |
| services/services/screen_capture/client/ | docs/knowledge/AVScreenCapture/entities/ipc-layer-entities.md | ScreenCaptureClient 客户端代理 |
| services/services/screen_capture_monitor/ | docs/knowledge/AVScreenCapture/entities/monitor-and-controller.md | Monitor 服务端/客户端，录屏状态追踪 |
| services/services/screen_capture_monitor/ipc/ | docs/knowledge/AVScreenCapture/entities/monitor-and-controller.md + docs/knowledge/AVScreenCapture/technologies/ipc-communication.md | Monitor IPC 序列化约束、回调不可阻塞 |
| services/etc/screencapture/ | docs/knowledge/AVScreenCapture/technologies/privacy-and-permission.md | 系统参数配置，弹窗与录屏器包名 |
| interfaces/inner_api/native/ | docs/knowledge/AVScreenCapture/entities/api-layer.md + docs/knowledge/AVScreenCapture/entities/ipc-layer-entities.md | InnerAPI 契约头文件（screen_capture.h），API 稳定性约束 |
| interfaces/kits/c/ | docs/knowledge/AVScreenCapture/entities/api-layer.md | 公共 SDK C 头文件（native_avscreen_capture.h），API 兼容性约束 |
| test/unittest/screen_capture_test/ | — | ScreenCaptureServer 状态机单元测试，验证状态转换合法性 |
| test/unittest/screen_capture_impl_unittest/ | — | ScreenCaptureImpl 单元测试 |
| test/fuzztest/screen_capture_fuzztest/ | — | 屏幕录制模糊测试，验证输入参数校验 |

**AVScreenCapture 关键词触发规则**：

- 提及 **AVScreenCapture, ScreenCapture, 录屏, 屏幕录制** 或本模块领域术语（虚拟屏幕、能力位图、隐私窗口、白名单/黑名单、Picker、Monitor、Controller、混音、消息码、通知栏、统计打点等）→ 先读 `docs/knowledge/AVScreenCapture/glossary.md`，按术语「详见」链接直达对应实体/技术文档（模块上下文确定时 glossary 已随「加载规范」启动加载）；术语未收录时查「知识索引 → AVScreenCapture」场景表

#### 其它模块路径

#### AVMeta 相关路径

| 修改路径 | 必读文档 | 原因 |
|----------|---------|------|
| frameworks/native/avmetadatahelper/ | docs/knowledge/AVMeta/entities/api-layer.md | API 层实体与约束，三接口合一，PixelMap 转换 |
| frameworks/native/capi/avmetadatahelper/ | docs/knowledge/AVMeta/entities/api-layer.md | C API 封装约束，OH_AVMetadataExtractor/OH_AVImageGenerator |
| frameworks/js/metadatahelper/ | docs/knowledge/AVMeta/entities/api-layer.md | NAPI 桥接层调用链，AVMetadataExtractorNapi/AVImageGeneratorNapi |
| frameworks/cj/metadatahelper/ | docs/knowledge/AVMeta/entities/api-layer.md | CJ-FFI 桥接层 |
| frameworks/taihe/media/ | docs/knowledge/AVMeta/entities/api-layer.md | Taihe 桥接层 |
| services/services/avmetadatahelper/ipc/ | docs/knowledge/AVMeta/technologies/ipc-communication.md + docs/knowledge/AVMeta/entities/ipc-layer-entities.md | IPC 序列化约束、回调不可阻塞、参数限制 |
| services/services/avmetadatahelper/server/ | docs/knowledge/AVMeta/technologies/metadata-lifecycle.md + docs/knowledge/AVMeta/entities/service-layer.md | 4 状态状态机、TaskQueue 串行化、懒初始化 |
| services/services/avmetadatahelper/client/ | docs/knowledge/AVMeta/entities/ipc-layer-entities.md | IPC 客户端代理，死亡通知 |
| services/engine/histreamer/avmetadatahelper/ | docs/knowledge/AVMeta/technologies/thumbnail-architecture.md + docs/knowledge/AVMeta/entities/engine-layer-entities.md | 缩略图生成、硬软解切换、懒初始化约束 |
| services/engine/histreamer/factory/ | docs/knowledge/AVMeta/entities/engine-factory-and-selection.md | 引擎工厂注册与打分选择，SCENE_AVMETADATA |
| interfaces/inner_api/native/avmetadatahelper.h | docs/knowledge/AVMeta/entities/api-layer.md | InnerAPI 契约定义 |
| interfaces/kits/c/avmetadata_extractor.h | docs/knowledge/AVMeta/entities/api-layer.md | C API 接口定义 |

#### 其它模块路径

### 高频修改场景→源码文件映射

#### AVPlayer 场景

| 修改场景 | 涉及源码文件 | 必读知识文档 |
|----------|------------|------------|
| Seek 逻辑修改 | `hiplayer_impl.cpp`、`seek_agent.cpp`、`pipeline.cpp`、`demuxer_filter.cpp` | docs/knowledge/AVPlayer/technologies/seek-architecture.md + docs/knowledge/AVPlayer/entities/engine-layer-entities.md |
| 状态机调整 | `player_server.cpp`（BaseState 子类） | docs/knowledge/AVPlayer/technologies/player-lifecycle.md + docs/knowledge/AVPlayer/technologies/design-patterns.md |
| IPC 接口增删 | `player_service_stub.cpp`、`player_service_proxy.cpp`、`player_client.cpp`、`player_listener_proxy.cpp` | docs/knowledge/AVPlayer/technologies/ipc-communication.md + docs/knowledge/AVPlayer/entities/ipc-layer-entities.md |
| 引擎注册/选择 | `engine_factory_repo.cpp`、`hst_engine_factory.cpp`、`lpp_engine_factory.cpp` | docs/knowledge/AVPlayer/entities/engine-factory-and-selection.md |
| 内存回收策略 | `player_server_mem.cpp`、`player_mem_manage.cpp` | docs/knowledge/AVPlayer/technologies/memory-and-background.md |
| Pipeline Filter 新增/修改 | 对应 `*_filter.cpp` + `pipeline.cpp` | docs/knowledge/AVPlayer/technologies/pipeline-architecture.md |
| NAPI/JS API 变更 | `avplayer_napi.cpp`、`player_impl.cpp` | docs/knowledge/AVPlayer/entities/api-layer.md |
| C API 变更 | `avplayer.cpp`、`player_object.cpp` | docs/knowledge/AVPlayer/entities/api-layer.md |
| 插件新增（Source/Demuxer/Codec） | 对应 `plugins/*/` 目录 | docs/knowledge/AVPlayer/technologies/media-source-and-protocol.md |
| 音视频同步调整 | `media_sync_manager.cpp`、`audio_sink_plugin.cpp` | docs/knowledge/AVPlayer/technologies/av-sync-and-buffer.md |
| 错误码/DFX 打点 | `player_server.cpp`、`dfx_agent.cpp` | docs/knowledge/AVPlayer/technologies/error-handling-and-dfx.md |

#### AVRecorder 场景

> 源码文件映射已下沉至 `docs/knowledge/AVRecorder/` 各实体/技术文档的「代码与符号 / 代码关联」小节，场景→文档路由由上方路径触发规则与关键词触发规则承载；任务特定验证检查与需先确认清单见 `docs/knowledge/AVRecorder/architecture.md`「验证」与「需先确认」节。
> 最低检查：构建 `./build.sh --product-name <product-name> --build-target av_recorder --ccache`；单元测试 `./test.sh av_recorder_unittest`；Lint `./tools/lint_changed.sh <changed-files>`（如可用）。

#### AVScreenCapture 场景

> 源码文件映射已下沉至 `docs/knowledge/AVScreenCapture/` 各实体/技术文档的「源码定位」小节，场景→文档路由由上方路径触发规则与关键词触发规则承载；任务特定验证检查见 `docs/knowledge/AVScreenCapture/technologies/error-handling-and-dfx.md` 等对应文档。
> 最低检查：构建 `./build.sh --product-name <product-name> --build-target media_service_screen_capture --ccache`；单元测试 `test/unittest/screen_capture_test/`（含 `screen_capture_ipc_unit_test`）、`test/unittest/screen_capture_impl_unittest/`；模糊测试 `test/fuzztest/screen_capture_fuzztest/`。

#### 其它模块场景

#### AVMeta 场景

| 修改场景 | 涉及源码文件 | 必读知识文档 |
|----------|------------|------------|
| 缩略图/帧抓取逻辑修改 | `av_thumbnail_generator.cpp`、`avmetadatahelper_impl.cpp`(engine) | docs/knowledge/AVMeta/technologies/thumbnail-architecture.md + docs/knowledge/AVMeta/entities/engine-layer-entities.md |
| 状态机调整 | `avmetadatahelper_server.cpp`（ChangeState/状态校验） | docs/knowledge/AVMeta/technologies/metadata-lifecycle.md + docs/knowledge/AVMeta/technologies/design-patterns.md |
| IPC 接口增删 | `avmetadatahelper_service_stub.cpp`、`avmetadatahelper_service_proxy.cpp`、`avmetadatahelper_client.cpp`、`helper_listener_proxy.cpp` | docs/knowledge/AVMeta/technologies/ipc-communication.md + docs/knowledge/AVMeta/entities/ipc-layer-entities.md |
| 引擎注册/选择 | `engine_factory_repo.cpp`、`hst_engine_factory.cpp` | docs/knowledge/AVMeta/entities/engine-factory-and-selection.md |
| 元数据提取逻辑 | `avmetadata_collector.cpp` | docs/knowledge/AVMeta/technologies/metadata-features.md + docs/knowledge/AVMeta/entities/engine-layer-entities.md |
| 硬软解切换 | `av_thumbnail_generator.cpp`（IsSupportHWDecoder/SwitchToSoftWareDecoder） | docs/knowledge/AVMeta/technologies/thumbnail-architecture.md |
| NAPI/JS API 变更 | `avmetadataextractor_napi.cpp`、`avimagegenerator_napi.cpp`、`avmetadatahelper_impl.cpp`(client) | docs/knowledge/AVMeta/entities/api-layer.md |
| C API 变更 | `native_avmetadata_extractor.cpp`、`native_avimage_generator.cpp` | docs/knowledge/AVMeta/entities/api-layer.md |
| 像素图/色彩空间处理 | `avmetadatahelper_impl.cpp`(client)（ProcessPixelMap/CreatePixelMapYuv/ScalePixelMap） | docs/knowledge/AVMeta/technologies/thumbnail-architecture.md + docs/knowledge/AVMeta/entities/api-layer.md |
| 超时/取消逻辑 | `avmetadatahelper_server.cpp`、`av_thumbnail_generator.cpp`、`avmetadatahelper_impl.cpp`(engine) | docs/knowledge/AVMeta/technologies/thumbnail-architecture.md + docs/knowledge/AVMeta/technologies/metadata-lifecycle.md |
| 批量帧抓取 | `avmetadatahelper_server.cpp`（FetchFrameYuvs）、`av_thumbnail_generator.cpp` | docs/knowledge/AVMeta/technologies/thumbnail-architecture.md + docs/knowledge/AVMeta/technologies/ipc-communication.md |
| 帧索引转换 | `avmetadatahelper_impl.cpp`(engine)（TimeAndIndexConversion） | docs/knowledge/AVMeta/technologies/metadata-features.md + docs/knowledge/AVMeta/entities/engine-layer-entities.md |
| 错误码/DFX 打点 | `avmetadatahelper_server.cpp`、`avmetadata_collector.cpp` | docs/knowledge/AVMeta/technologies/error-handling-and-dfx.md |
| 媒体源/协议处理 | `avmetadatahelper_impl.cpp`(engine)（SetSource/InitDemuxer） | docs/knowledge/AVMeta/technologies/media-source-and-protocol.md |

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
9. **禁止冗余注释**：代码不加注释，靠命名和结构自解释。文件级版权头除外。

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

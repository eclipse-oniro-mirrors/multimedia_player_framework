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
├── AVRecorder/        # 录制模块（待建设）
├── AVTranscoder/      # 转码模块（待建设）
├── AVMetadata/        # 元数据模块（待建设）
└── ...                # 其他模块按需扩展
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
2. **任务类别**：API 变更 / 引擎开发 / IPC 修改 / Pipeline 调整 / 内存管理 / DFX 增强 / Bug 修复 / 其他
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

知识目录：`knowledge/AVRecorder/`（待建设）

```
knowledge/AVRecorder/
├── glossary.md                              # 术语表
├── business-context.md                      # 业务背景
├── architecture.md                          # 架构设计及约束
├── coding-standards.md                      # 编码规范
├── entities/
│   └── ...                                  # 待建设
└── technologies/
    └── ...                                  # 待建设
```

### AVTranscoder 模块（转码）

知识目录：`knowledge/AVTranscoder/`（待建设）

```
knowledge/AVTranscoder/
├── glossary.md                              # 术语表
├── business-context.md                      # 业务背景
├── architecture.md                          # 架构设计及约束
├── coding-standards.md                      # 编码规范
├── entities/
│   └── ...                                  # 待建设
└── technologies/
    └── ...                                  # 待建设
```

### AVMetadata 模块（元数据/缩略图）

知识目录：`knowledge/AVMetadata/`（待建设）

```
knowledge/AVMetadata/
├── glossary.md                              # 术语表
├── business-context.md                      # 业务背景
├── architecture.md                          # 架构设计及约束
├── coding-standards.md                      # 编码规范
├── entities/
│   └── ...                                  # 待建设
└── technologies/
    └── ...                                  # 待建设
```

### 路径→文档触发规则

修改以下目录时，必须先阅读对应知识文档：

#### AVPlayer 相关路径

| 修改路径 | 必读文档 | 原因 |
|----------|---------|------|
| frameworks/native/player/ | knowledge/AVPlayer/entities/api-layer.md | API 层实体与约束，状态机调用顺序 |
| frameworks/native/capi/player/ | knowledge/AVPlayer/entities/api-layer.md | NDK C API 封装约束，OH_AVPlayer 回调机制 |
| frameworks/js/napi/ | knowledge/AVPlayer/entities/api-layer.md | NAPI 桥接层调用链 |
| services/services/player/ipc/ | knowledge/AVPlayer/technologies/ipc-communication.md + knowledge/AVPlayer/entities/ipc-layer-entities.md | IPC 序列化约束、回调不可阻塞、Freeze 机制 |
| services/services/player/ | knowledge/AVPlayer/technologies/player-lifecycle.md + knowledge/AVPlayer/entities/service-layer.md | 8 状态状态机、TaskMgr 异步约束、ConfigInfo 原子性 |
| services/services/player/player_mem_manage/ | knowledge/AVPlayer/technologies/memory-and-background.md | 内存回收/恢复流程、前台后台策略 |
| services/engine/histreamer/player/ | knowledge/AVPlayer/technologies/pipeline-architecture.md + knowledge/AVPlayer/entities/engine-layer-entities.md | Pipeline 统一控制约束、Filter 接口契约 |
| services/engine/histreamer/lpp/ | knowledge/AVPlayer/entities/engine-factory-and-selection.md | LPP 引擎实体、HDI 同步机制 |
| services/engine/ | knowledge/AVPlayer/entities/engine-factory-and-selection.md | 引擎工厂注册与打分选择，dlopen 约束 |
| plugins/ | knowledge/AVPlayer/technologies/media-source-and-protocol.md | 插件 Sniff 注册机制、路径安全校验 |

#### 其他模块路径

> AVRecorder、AVTranscoder、AVMetadata 等模块的路径触发规则待对应知识库建设后补充。

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
| NDK C API 变更 | `avplayer.cpp`、`player_object.cpp` | knowledge/AVPlayer/entities/api-layer.md |
| 插件新增（Source/Demuxer/Codec） | 对应 `plugins/*/` 目录 | knowledge/AVPlayer/technologies/media-source-and-protocol.md |
| 音视频同步调整 | `media_sync_manager.cpp`、`audio_sink_plugin.cpp` | knowledge/AVPlayer/technologies/av-sync-and-buffer.md |
| 错误码/DFX 打点 | `player_server.cpp`、`dfx_agent.cpp` | knowledge/AVPlayer/technologies/error-handling-and-dfx.md |

#### 其他模块场景

> AVRecorder、AVTranscoder、AVMetadata 等模块的高频修改场景映射待对应知识库建设后补充。

## 架构概要

### 双进程架构

- **MediaServer（System Ability）**：服务端进程，承载播放器/录制器/转码器实例管理、IPC 请求处理、引擎生命周期管理
- **应用进程**：客户端进程，通过 PlayerClient/RecorderClient 等 IPC 代理端与服务端通信

### 核心处理链路

```
应用 (ArkTS/JS/CangJie/C)
  → Bridge Layer (NAPI/FFI/C API)
  → Native API (PlayerImpl/RecorderImpl)
  → IPC (Binder) → Service Server (PlayerServer)
  → EngineFactory (打分选择引擎)
  → Engine (HiPlayerImpl / LppEngine)
  → Pipeline (Demuxer → Decoder → Sink)
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
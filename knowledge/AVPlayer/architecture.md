# 架构设计及约束

> **全局性**架构设计原则及约束说明

## 架构设计

### 设计原则

| 原则 | 描述 | 理由 |
|------|------|------|
| Client-Server 进程隔离 | 播放器客户端运行在应用进程，服务端运行在媒体服务进程，通过 IPC 通信 | 隔离媒体服务崩溃风险，支持多客户端共享服务端，IPC 是模块边界 |
| 引擎工厂打分选择 | EngineFactoryRepo 通过打分机制自动选择最优引擎（Histreamer/GStreamer/LPP） | 不同场景（正常播放/低功耗/直播）需不同引擎，打分机制实现自适应选择 |
| Pipeline Filter链 | 数据流通过 Filter 链式传递，每个 Filter 职责单一，通过 BufferQueue 连接 | 解耦数据处理环节，新增/替换 Filter 不影响链路其它部分 |
| InnerAPI 接口边界 | Pipeline 层通过 InnerAPI 调用原子能力，不直接依赖插件实现 | 屏蔽插件实现差异，框架与原子能力可独立演进 |
| 插件化 Sniff 机制 | Source/Demuxer/Codec 插件通过 Sniff 嗅探打分自动选择 | 支持多种媒体格式，新格式只需注册插件无需修改框架 |
| 异步任务队列 | PlayerServer 通过 TaskMgr 异步处理所有播放操作，IPC 线程快速返回 | 减少 IPC 序列化开销，避免阻塞调用方线程 |
| 状态机驱动 | PlayerServer 采用 8 状态有限状态机管理生命周期 | 状态转换有明确约束，防止非法操作导致的未定义行为 |

### 逻辑架构

```
┌─────────────────────────────────────────────────────────────┐
│                     API 接入层                                │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ AVPlayer     │  │ AVRecorder   │  │ AVTranscoder      │  │
│  │ (ArkTS/JS/   │  │ (ArkTS/JS/   │  │ AVMetadataExtractor│  │
│  │  C API)      │  │  C API)      │  │ AVImageGenerator  │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬──────────┘  │
├─────────┼─────────────────┼───────────────────┼─────────────┤
│         │      NAPI/CJ-FFI/ANI Bridge Layer   │             │
├─────────┼─────────────────┼───────────────────┼─────────────┤
│                     IPC 通信层                                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ PlayerClient ←── IPC ──→ PlayerServiceStub/Proxy     │   │
│  │ PlayerCallback ←── IPC ──→ PlayerListenerStub/Proxy  │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                     引擎选择层                                │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ EngineFactoryRepo ──打分──→ HstEngineFactory          │   │
│  │                            GstEngineFactory           │   │
│  │                            LppEngineFactory           │   │
│  └──────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                   Pipeline 流水线层                           │
│  ┌──────────┐   ┌────────────────┐   ┌───────────────┐    │
│  │Demuxer   │──→│AudioDecoder    │──→│AudioSinkFilter│    │
│  │Filter    │──→│DecoderSurface  │──→│VideoSink      │    │
│  └──────────┘   └────────────────┘   └───────────────┘    │
│  SeekAgent  HiPlayerCallbackLooper  DfxAgent  LiveCtrl    │
├─────────────────────────────────────────────────────────────┤
│                   InnerAPI 契约层                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │MediaDemuxer │  │MediaCodec    │  │VideoDecoder      │  │
│  │InnerApi     │  │InnerApi      │  │InnerApi          │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                原子能力 + 插件层                               │
│  ┌────────────────┐ ┌─────────────┐ ┌─────────────────┐   │
│  │Source原子能力   │ │Demuxer原子  │ │Codec原子能力     │   │
│  │协议选择         │ │Sniff()打分  │ │name/属性选择     │   │
│  │SourcePlugin     │ │DemuxerPlugin│ │CodecPlugin      │   │
│  │(HTTP/本地/HLS)  │ │(ffmpeg)     │ │(hcodec/fcodec)  │   │
│  └────────────────┘ └─────────────┘ └─────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│              Media_Foundation 基础层                          │
│   AVBufferQueue │ AVBuffer │ FilterFactory │ PluginManager   │
└─────────────────────────────────────────────────────────────┘
```

### 模块职责

| 模块 | 类型 | 模块职责 | 关键文件 |
|------|------|---------|---------|
| AVPlayer (C API) | ohos_shared_library | C API 播放器，OH_AVPlayer_* 接口族，PlayerObject 封装 PlayerImpl | `frameworks/native/capi/player/avplayer.cpp`、`avplayer_napi.cpp` |
| AVPlayer (ArkTS/JS) | ohos_shared_library | NAPI 桥接层，AVPlayer/AVRecorder JS 类，TaskQueue 异步调度 | `frameworks/js/napi/player/avplayer_napi.cpp`、`avrecorder_napi.cpp` |
| PlayerClient | ohos_shared_library | 应用进程播放器代理，持有 IPC Proxy + ListenerStub，转发调用到服务端 | `services/services/player/ipc/client/player_client.cpp` |
| PlayerServiceStub | ohos_shared_library | IPC 服务端入口，playerFuncs_ 分发，权限校验，Freeze/UnFreeze 控制 | `services/services/player/ipc/stub/player_service_stub.cpp` |
| PlayerServer | ohos_shared_library | 服务端核心，8状态状态机 + TaskMgr 异步队列 + ConfigInfo 配置 | `services/services/player/server/player_server.cpp` |
| PlayerServerMem | ohos_shared_library | 内存管理扩展，RecoverConfigInfo 状态保存/恢复，前台/后台资源回收 | `services/services/player/player_mem_manage/player_server_mem.cpp` |
| HiPlayerImpl | ohos_shared_library | Histreamer 引擎核心，Pipeline 生命周期管理，SeekAgent，回调循环 | `services/engine/histreamer/player/hiplayer_impl.cpp` |
| Pipeline + Filters | ohos_shared_library | Filter 链容器，Demuxer/Decoder/Sink Filter 串联，BufferQueue 数据传递 | `foundation/multimedia/media_foundation/histreamer/pipeline/pipeline.cpp`、`demuxer_filter.cpp`、`audio_decoder_filter.cpp`、`decoder_surface_filter.cpp` |
| EngineFactoryRepo | ohos_shared_library | 引擎仓库，dlopen 加载引擎工厂 .so，打分选择最优引擎 | `services/engine/engine_factory_repo.cpp` |
| LppEngine | ohos_shared_library | 低功耗播放引擎，硬件解码/渲染/同步，LppSyncManager HDI 时钟 | `services/engine/histreamer/lpp/lpp_engine.cpp`、`lpp_sync_manager.cpp` |
| Media_Foundation | ohos_shared_library | 基础设施，AVBuffer/AVBufferQueue/FilterFactory/PluginManager | `foundation/multimedia/media_foundation/histreamer/` |
| Source/Demuxer Plugins | ohos_shared_library | 协议/解封装插件，HTTP/HLS/本地 Source，ffmpeg Demuxer | `plugins/httpsource/`、`plugins/hls_source/`、`plugins/ffmpeg_demuxer/` |
| Codec Plugins | ohos_shared_library | 编解码插件，hcodec 硬解，fcodec 软解 | `plugins/hcodec/`、`plugins/fcodec/` |

### 技术选型

| 类别 | 技术选型 | 说明 |
|------|---------|------|
| 进程间通信 | OHOS IPC（MessageParcel / IRemoteStub） | Client-Server 双进程，PlayerServiceStub/Proxy + PlayerListenerStub/Proxy |
| 数据传递 | AVBufferQueue（Producer-Consumer） | Pipeline Filter 间零拷贝数据传递，音频 BQ:8/30，视频 BQ:4 |
| 引擎加载 | dlopen/dlsym 动态加载 | EngineFactoryRepo 按 .so 路径加载引擎工厂，支持 Histreamer/GStreamer/LPP |
| 插件选择 | Sniff 嗅探打分 | PluginManager 循环调用 Sniff，比较 confidence 选最优插件 |
| 解封装 | ffmpeg (av_read_frame) | DemuxerPlugin 封装 ffmpeg，支持 MP4/MKV/FLV/TS 等主流格式 |
| 视频硬解 | codec_server (InnerAPI) | VideoDecoderAdapter 通过 InnerAPI 调用 AVCodec 服务硬解 |
| 视频软解 | fcodec | ffmpeg 软解插件，备选方案 |
| 音频输出 | AudioRenderer | AudioSinkPlugin 封装 AudioRenderer 写入 PCM 数据 |
| 视频渲染 | Surface | DecoderSurfaceFilter 通过 Surface 输出视频帧到显示 |
| 内存管理 | madvise + RecoverConfigInfo | 系统内存压力时回收/恢复播放器资源 |

### 基础设施

> 全局架构基础设施，约束模型编码，包括日志与打点、进程监控、内存回收、状态冻结等统一的代码基础设施

| 基础设施 | 功能说明 | 关键接口描述 |
|----------|---------|------------|
| 进程监控 | DeathRecipient 监控服务端/客户端死亡 | `PlayerClient` 注册死亡通知，`PlayerServiceStub` 清理死亡客户端 |
| 内存回收 | PlayerMemManage 响应系统内存压力，前台/后台分级回收 | `HandleOnTrim`、`HandleForceReclaim`、`RecoverByMemManage` |
| 心跳监控 | MonitorClientObject 定期 IPC 保活，检测连接异常 | `MonitorClientObject::Enable` |
| 状态冻结 | Freeze/UnFreeze 机制，后台暂停 IPC 回调减少开销 | `PlayerServiceStub::DoFreeze`/`DoUnFreeze` |

### 非功能设计

> 此章节仅描述**全局性**的非功能实现方案及原则

#### 可测试性设计

| 可测试性场景 | 方案设计 |
|-------------|---------|
| 引擎可替换测试 | EngineFactoryRepo 打分机制支持注入 MockEngineFactory，验证引擎选择逻辑 |
| IPC 接口级测试 | PlayerClient/PlayerServiceStub 通过 IPC Proxy/Stub 可独立 Mock 对端进行测试 |

#### 可靠性设计

| 可靠性场景 | 方案设计 |
|-----------|---------|
| 服务端崩溃隔离 | Client-Server 双进程，媒体服务崩溃不影响应用进程 |
| IPC 异常恢复 | DeathRecipient 监控对端死亡，DoIpcAbnormality/DoIpcRecovery 自动恢复 |
| Surface 生命周期 | Surface 释放时通知播放器，避免访问已释放的渲染资源 |

#### 性能设计

| 性能场景 | 方案设计 |
|----------|---------|
| IPC 异步化 | PlayerServer 所有操作通过 TaskMgr 异步执行，IPC 线程快速返回不阻塞 |
| 连续 Seek 去重 | TwoPhaseTaskItem 支持准备/执行分离，新 Seek 替换旧任务仅执行最新目标 |
| 回调去重 | 同类型事件仅回调一次，避免连续缓冲更新导致应用层频繁响应 |
| 批量参数 | ConfigInfo 一次性传递音量/循环/速度等配置，减少 IPC 次数 |
| 状态机驱动 | 仅状态变化时触发 IPC，避免轮询式查询 |
| BufferQueue 容量调优 | 音频输入 BQ:8、输出 BQ:30，视频 BQ:4，按轨道类型配置缓冲深度 |

#### 内存设计

| 内存场景 | 方案设计 |
|----------|---------|
| 引擎按需加载 | EngineFactoryRepo 通过 dlopen 懒加载引擎 .so，无播放时不占用内存 |
| 前台/后台分级回收 | PlayerMemManage 响应系统 OnTrim/ForceReclaim，后台优先释放网络/解码资源 |
| 状态保存恢复 | RecoverConfigInfo 保存完整播放状态（URL/位置/配置/Surface），恢复后自动 Seek 回原位 |
| madvise 内存优化 | MediaMadviseUtils 对不活跃内存区域调用 madvise(MADV_DONTNEED) 释放物理页 |
| Freeze 回调冻结 | 后台时 Freeze IPC 回调，减少回调序列化/反序列化的内存和 CPU 开销 |

#### 安全与隐私设计

| 安全与隐私场景 | 设计方案 |
|--------------|---------|
| 进程隔离 | Client-Server 双进程，媒体服务崩溃不影响应用进程 |
| 路径安全校验 | SetSource 时校验文件路径合法性，防止路径穿越 |
| 状态机约束 | 8 状态有限状态机，非法操作返回错误而非崩溃 |
| 线程安全 | PlayerServer 互斥锁保护状态/引擎/配置，BufferQueue 生产消费模型天然线程安全 |

## 架构约束

> **全局性**的架构约束说明，需要包含what/why/how

- **IPC 是模块边界**
  - **what**：所有跨进程调用必须通过 IPC Proxy/Stub，严禁共享裸指针或引用
  - **why**：进程隔离是崩溃安全的基础，共享指针会绕过进程保护导致级联故障
  - **how**：所有跨进程数据通过 MessageParcel 序列化，客户端持有 Proxy，服务端实现 Stub

- **引擎可替换**
  - **what**：新增引擎必须实现 IEngineFactory 接口并通过 dlopen 注册，严禁在服务层硬编码引擎创建逻辑
  - **why**：硬编码引擎选择会破坏扩展性，新增引擎需修改服务层核心代码
  - **how**：EngineFactoryRepo 通过 dlopen 动态加载 .so，打分选择最优引擎，服务层仅依赖 IEngineFactory 接口

- **Pipeline 统一控制**
  - **what**：Seek/Stop 等生命周期操作必须通过 Pipeline 统一下发，严禁引擎直接操作特定 Filter
  - **why**：直接操作 Filter 会绕过状态同步，导致数据流不一致
  - **how**：所有操作通过 Pipeline::SendMessage 下发到目标 Filter，引擎不持有 Filter 直接引用

- **InnerAPI 是服务契约**
  - **what**：服务层与引擎层通过 InnerAPI 头文件解耦，严禁服务层直接依赖引擎实现细节
  - **why**：直接依赖实现会破坏层次边界，导致框架与引擎耦合无法独立演进
  - **how**：Pipeline 层仅包含 InnerAPI 头文件，通过 InnerAPI 接口调用原子能力

- **状态机保护**
  - **what**：PlayerServer 所有操作必须经过 8 状态状态机校验，非法操作返回 MSERR_INVALID_STATE
  - **why**：未校验的操作可能导致未定义行为，如未 Prepare 就 Start
  - **how**：每个操作入口先检查当前状态是否合法，不合法直接返回错误码

- **内存回收可恢复**
  - **what**：所有播放状态必须保存到 RecoverConfigInfo，确保内存回收后可完整恢复
  - **why**：系统内存压力会强制回收播放器资源，不可恢复将导致用户播放中断
  - **how**：状态变更时同步写入 RecoverConfigInfo，回收后通过 RecoverByMemManage 自动恢复

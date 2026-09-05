# 引擎层实体

> HiPlayerImpl、流水线、过滤器、SeekAgent 等 Histreamer 引擎核心类

## 实体概念

### 引擎核心

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| HiPlayerImpl | Histreamer 引擎核心类，实现 IPlayerEngine 接口 | SetSource/PrepareAsync/Play/Pause/Stop/Seek/SeekContinous 生命周期；DoSetSource 内部设置源；LinkAudioDecoderFilter/LinkVideoDecoderFilter 动态链接过滤器；持有流水线、SeekAgent、HiPlayerCallbackLooper、DfxAgent、LiveController、MediaSyncManager | 引擎实现 |
| HiPlayerCallbackLooper | 引擎回调循环，将引擎事件分发到上层 | StartWithPlayerEngineObs 启动；OnError/OnInfo 接收事件；EnableReportMediaProgress 进度上报；LoopOnce 循环处理；Enqueue 事件入队 | 引擎回调 |
| DfxAgent | 诊断代理，负责性能监测与行为打点 | OnDfxEvent 诊断事件；ReportLagEvent 卡顿上报；SetSourceType 源类型分类；GetTotalStallingDuration/GetTotalStallingTimes 卡顿统计 | 诊断工具 |
| LiveController | 直播流控制器，监控直播延迟并调整 | StartCheckLiveDelayTime/StopCheckLiveDelayTime 延迟检测；DoRestartLiveLink 网络中断重启 | 直播控制 |

### 流水线与过滤器

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| Pipeline | 过滤器链容器，管理过滤器生命周期和数据流控制 | AddHeadFilters 添加头部过滤器；LinkFilters 链接上下游；Prepare/Start/Pause/Resume/Stop 生命周期；Flush 刷新缓冲区；SendCommand 发送统一命令（如 SEEK） | 流水线容器 |
| DemuxerFilter | 流水线头部过滤器，解析容器格式，分离音视频流 | SetDataSource 触发源/解封装初始化；OnCallback 轨道信息回调（NEXT_FILTER_NEEDED）；Pause/Resume/Flush Seek 时控制 | 输入过滤器 |
| AudioDecoderFilter | 音频解码过滤器，音频基本流 → PCM | OnLinked 配置解码器；解码线程从输入缓冲队列取基本流 → 解码 → 写入输出缓冲队列 | 解码过滤器 |
| DecoderSurfaceFilter | 视频解码+渲染过滤器，视频基本流 → Surface 渲染 | VideoDecoderAdapter 适配器桥接 AVCodecVideoDecoder；Surface 输出解码帧；RenderLoop 视频渲染循环线程 | 解码+渲染过滤器 |
| AudioSinkFilter | 音频输出过滤器，PCM → AudioRenderer | AudioSinkPlugin 封装 AudioRenderer；AudioRenderer::Write() 阻塞控制输出速率 | 输出过滤器 |
| BufferQueue | 生产者-消费者模型，过滤器间数据传递 | RequestBuffer/PushBuffer (生产者)；AcquireBuffer/ReleaseBuffer (消费者)；音频输入缓冲队列:8，视频输入缓冲队列:4，音频输出缓冲队列:30 | 数据传递 |
| AVBuffer | 流水线基本数据单元，一个 AVBuffer 对应一帧数据 | data 帧数据；pts 显示时间戳；flags 标志位（关键帧/EOS 等） | 数据单元 |
| MediaSyncManager | 音视频同步管理器 | 音频主时钟（以音频播放进度为基准）；视频帧率控制（RenderLoop 按帧率送显）；同步修正（视频过早延迟，过晚丢帧追赶） | 同步管理 |

### 源与解封装

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| MediaDemuxer | 核心解封装类，持有 DataPacker、TypeFinder、DemuxerPlugin | SetDataSource 初始化源和解封装器；Start 开始解封装循环；ReadSample 读取采样数据（av_read_frame） | 解封装 |
| DataPacker | 数据缓冲组件，源与 MediaDemuxer 之间的缓冲 | 推送模式：源 ReadLoop 主动推送；拉取模式：解封装器按需拉取 | 数据缓冲 |
| TypeFinder | 媒体类型嗅探器 | FindMediaType 查找媒体类型；SniffMediaType 循环嗅探比较置信度；GuessMediaType 根据 URI 后缀猜测 | 媒体嗅探 |
| SourcePlugin | 数据源插件抽象 | protocol_ 支持的协议；URI 资源地址；Read 读取数据；GetSeekable/SeekTo Seek 能力 | 插件 |
| DemuxerPlugin | 解封装插件，基于 ffmpeg | bufferQueueVector_ 按轨道的缓冲队列；AVReadPacket ffmpeg 读取回调；SeekToPos 按偏移量定位 | 插件 |
| SourceParseAgent | 流协议动态加载器 | dlopen/dlsym 动态加载协议动态库；SniffStreamProtocol 嗅探流协议 | 协议加载 |
| DownloaderImpl | 下载管理器 | 多任务调度；SourceParseAgent 集成协议检测；NetworkUtils 网络工具 | 下载管理 |

### Seek 相关

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| SeekAgent | Seek 管理器，HiPlayerImpl 内部组件 | Seek 发起（SEEK_CLOSEST）；OnAudioBufferFilled/OnVideoBufferFilled 缓冲填充通知；AlignAudioPosition 对齐音频位置；OnInterrupted 中断处理；IsSeeking 查询状态 | Seek 管理 |
| DraggingPlayerAgent | 拖拽场景代理，管理连续 Seek | Create 创建代理；UpdateSeekPos 更新 Seek 目标位置；Release 释放代理；GetDraggingMode 获取拖拽模式 | Seek 代理 |

### 接口抽象

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| IPlayerEngine | 引擎接口，PlayerServer 通过此接口操作引擎 | SetSource/PrepareAsync/Play/Pause/Stop 生命周期；Seek/SeekContinous Seek 控制；SetVolume/SetSpeed/SetLooping 参数设置 | 接口 |
| IPlayerEngineObs | 引擎观察者接口，引擎通过此接口上报事件 | OnError 错误通知；OnInfo 信息通知；OnSystemOperation 系统操作通知；OnDfxInfo DFX 信息通知 | 观察者接口 |

## 上下文与场景

### 交互流程

**过滤器链数据流**：

```
DemuxerFilter ──→ AudioDecoderFilter ──→ AudioSinkFilter
               └──→ DecoderSurfaceFilter ──→ VideoSink
                        └──→ VideoDecoderAdapter
```

**引擎操作流程**：

```
PlayerServer → IPlayerEngine → HiPlayerImpl
  → Pipeline::SendCommand (SEEK/STOP/...)
  → 过滤器链执行
  → HiPlayerCallbackLooper → IPlayerEngineObs → PlayerServer
```

**Seek 完整流程**：

```
PlayerServer::Seek → IPlayerEngine::Seek → HiPlayerImpl::Seek
  → SeekAgent::Seek → Pipeline::SendCommand(SEEK)
  → DemuxerFilter::Pause → Flush → SeekToPos → Resume
  → 缓冲队列重新填充 → SeekAgent::OnAudioBufferFilled
  → AlignAudioPosition → HiPlayerCallbackLooper::OnInfo(SEEK_DONE)
```

### 异常处理路径

| 异常场景 | 处理方式 |
|---------|---------|
| 直播流延迟过大 | LiveController::DoCheckLiveDelayTime 检测延迟，DoRestartLiveLink 重启链路 |
| 连续 Seek 冲突 | SeekAgent 支持新 Seek 替换旧 Seek，DraggingPlayerAgent 管理连续拖拽 |
| 解码失败 | 过滤器通过 OnError 上报，HiPlayerCallbackLooper 转发到 PlayerServer |

### 状态流转

**SeekAgent 状态**：空闲 → 定位中 → 缓冲填充中 → 已对齐 → 空闲

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 业务规则 | 流水线统一控制：Seek/Stop 等操作必须通过 Pipeline::SendCommand 下发，严禁引擎直接操作特定过滤器 |
| 业务规则 | 内部 API 接口边界：流水线层通过内部 API 调用原子能力，不直接依赖插件实现 |
| 性能约束 | 缓冲队列容量调优：音频输入缓冲队列:8、输出缓冲队列:30，视频缓冲队列:4 |
| 性能约束 | 连续 Seek 去重：TwoPhaseTaskItem 支持准备/执行分离，新 Seek 替换旧任务 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上层依赖 | [[service-layer]] — PlayerServer 通过 IPlayerEngine 接口控制引擎 |
| 上层依赖 | [[engine-factory-and-selection]] — 引擎工厂创建引擎实例 |
| 平级关联 | HiPlayerImpl ↔ Pipeline — 引擎持有流水线并通过其管理过滤器链 |
| 平级关联 | SeekAgent ↔ DraggingPlayerAgent — 前者管理单次 Seek，后者管理连续拖拽 Seek |
| 概念对比 | IPlayerEngine (接口) vs HiPlayerImpl (实现) — 接口与实现分离，服务层仅依赖接口 |
| 概念对比 | 推送模式 vs 拉取模式 (DataPacker) — 源主动推送 vs 解封装器按需拉取 |

## 数据模型

### 缓冲队列容量配置

| 缓冲队列 | 容量 | 用途 |
|----------|------|------|
| 音频输入缓冲队列 | 8 | 解封装器 → 音频解码器 |
| 视频输入缓冲队列 | 4 | 解封装器 → 视频解码器 |
| 音频输出缓冲队列 | 30 | 音频解码器 → 音频输出 |

### AVBuffer 结构

| 属性 | 说明 |
|------|------|
| data | 帧数据 |
| pts | 显示时间戳 |
| flags | 标志位（关键帧/EOS 等） |

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| HiPlayerImpl | `services/engine/histreamer/player/hiplayer_impl.cpp/.h` | HiPlayerImpl::SetSource/PrepareAsync/Play/Seek |
| HiPlayerCallbackLooper | `services/engine/histreamer/player/hiplayer_callback_looper.cpp/.h` | HiPlayerCallbackLooper::LoopOnce/Enqueue |
| DfxAgent | `services/engine/histreamer/player/dfx_agent.cpp/.h` | DfxAgent::OnDfxEvent/ReportLagEvent |
| LiveController | `services/engine/histreamer/player/live_controller.cpp/.h` | LiveController::DoCheckLiveDelayTime |
| SeekAgent | `services/engine/histreamer/player/seek_agent.cpp/.h` | SeekAgent::Seek/AlignAudioPosition |
| DraggingPlayerAgent | `services/engine/histreamer/player/dragging_player_agent.cpp/.h` | DraggingPlayerAgent::UpdateSeekPos |
| MediaDemuxer | `foundation/multimedia/media_foundation/histreamer/engine/plugins/media_demuxer.cpp` | MediaDemuxer::SetDataSource/Start/ReadSample |
| DataPacker | `foundation/multimedia/media_foundation/histreamer/engine/plugins/data_packer.cpp` | DataPacker::Push/AcquireBuffer |
| TypeFinder | `foundation/multimedia/media_foundation/histreamer/engine/plugins/type_finder.cpp` | TypeFinder::FindMediaType/SniffMediaType/GuessMediaType |
| SourcePlugin | `plugins/httpsource/http_source_plugin.cpp`, `plugins/hls_source/hls_source_plugin.cpp` | SourcePlugin::Read/GetSeekable/SeekTo |
| DemuxerPlugin | `plugins/ffmpeg_demuxer/ffmpeg_demuxer_plugin.cpp` | DemuxerPlugin::AVReadPacket/SeekToPos |
| SourceParseAgent | `foundation/multimedia/media_foundation/histreamer/engine/plugins/source_parse_agent.cpp` | SourceParseAgent::SniffStreamProtocol |
| DownloaderImpl | `plugins/httpsource/downloader/http_downloader.cpp` | DownloaderImpl 下载调度 |
| Pipeline | `foundation/multimedia/media_foundation/histreamer/pipeline/pipeline.cpp` | Pipeline::AddHeadFilters/LinkFilters/SendCommand |
| DemuxerFilter | `foundation/multimedia/media_foundation/histreamer/pipeline/filters/demuxer_filter.cpp` | DemuxerFilter::SetDataSource/OnCallback |
| AudioDecoderFilter | `foundation/multimedia/media_foundation/histreamer/pipeline/filters/audio_decoder_filter.cpp` | AudioDecoderFilter::OnLinked |
| DecoderSurfaceFilter | `foundation/multimedia/media_foundation/histreamer/pipeline/filters/decoder_surface_filter.cpp` | DecoderSurfaceFilter::RenderLoop |
| AudioSinkFilter | `foundation/multimedia/media_foundation/histreamer/pipeline/filters/audio_sink_filter.cpp` | AudioSinkFilter 音频输出 |
| VideoSink | `foundation/multimedia/media_foundation/histreamer/pipeline/filters/video_sink.cpp` | VideoSink 视频渲染输出 |
| IPlayerEngine | `services/engine/include/i_player_engine.h` | IPlayerEngine::SetSource/PrepareAsync/Play/Seek |
| IPlayerEngineObs | `services/engine/include/i_player_engine_obs.h` | IPlayerEngineObs::OnError/OnInfo |
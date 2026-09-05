# Pipeline架构与数据流转

> Histreamer引擎的Pipeline架构、Filter链、线程模型与Buffer流转。开发高频参考。

## 一、Pipeline架构概览

Pipeline 是 Histreamer 引擎的核心数据流框架，采用 **Filter链** 模式组织数据处理：

```
HiPlayerImpl
  ├── Pipeline（Filter链容器）
  │     DemuxerFilter ──→ AudioDecoderFilter ──→ AudioSinkFilter
  │                  └──→ DecoderSurfaceFilter ──→ VideoSink
  │                           └──→ VideoDecoderAdapter
  ├── SeekAgent（Seek跳转代理）
  ├── HiPlayerCallbackLooper（回调循环）
  └── DfxAgent（诊断代理）
```

### Filter 基类接口

每个 Filter 实现统一接口：

| 方法 | 说明 |
|------|------|
| SetDataSource() | 设置数据源（仅DemuxerFilter） |
| Prepare() | 准备Filter，链接上下游 |
| Start() | 启动数据处理 |
| Pause() | 暂停数据处理 |
| Resume() | 恢复数据处理 |
| Stop() | 停止数据处理 |
| Flush() | 刷新缓冲区 |
| OnLinked() | 上下游链接完成回调 |
| SetOutputBufferQueue() | 设置输出BufferQueue |

## 二、Pipeline搭建流程

Pipeline 的搭建是 **PrepareAsync 阶段的核心工作**：

```
1. 创建引擎
   PlayerServer → HiPlayerImpl::CreatePlayerEngine()
   → Pipeline::Pipeline()  创建空Pipeline

2. 设置播放源
   PlayerServer → HiPlayerImpl::SetSource()  记录播放源

3. Prepare触发搭建
   PlayerServer → HiPlayerImpl::Prepare()
   → 创建 DemuxerFilter
   → DemuxerFilter::SetDataSource()  触发Source/Demuxer插件选择和初始化
   → Pipeline::AddHeadFilters(demuxerFilter)

4. Pipeline::Prepare()  根据轨道信息动态搭建
   → DemuxerFilter::Prepare()：
     
     4a. 音频轨回调 OnCallback(音频轨数据)
     → HiPlayerImpl::LinkAudioDecoderFilter()
       → 创建 AudioDecoderFilter
       → Pipeline::LinkFilters(demuxerFilter, {audioDecoder_})
       → DemuxerFilter::LinkNext() 链接下游
       → AudioDecoderFilter::OnLinked() configure解码器
     
     4b. 视频轨回调 OnCallback(视频轨数据)
     → HiPlayerImpl::LinkVideoDecoderFilter()
       → 创建 DecoderSurfaceFilter
       → Pipeline::LinkFilters(demuxerFilter, {videoDecoder_})
       → DemuxerFilter::LinkNext() 链接下游
       → DecoderSurfaceFilter::OnLinked() configure解码器, 设置Surface

5. 下游Filter级联搭建
   AudioDecoderFilter::Prepare()
   → OnCallback → HiPlayerImpl::LinkAudioSinkFilter()
   → 创建 AudioSinkFilter
   → AudioSinkFilter::OnLinked() 初始化AudioSink原子能力和插件
   → AudioSinkFilter::Prepare() 执行sink原子能力Prepare
   → AudioSinkFilter → AudioDecoderFilter: OnLinkedResult(输出BQ)
     为解码器SetOutputBufferQueue
   → AudioDecoderFilter → DemuxerFilter: OnLinkedResult(inputBQ)
     为demuxer设置OutputBufferQueue

6. 视频同理
   DecoderSurfaceFilter::Prepare()
   → DemuxerFilter: OnLinkedResult(outputBQ)
```

## 三、线程模型与Buffer流转

### 3.1 线程分布

Pipeline 各环节运行在不同线程上，通过 BufferQueue 实现线程间数据传递：

| 线程 | 线程ID(示例) | 职责 |
|------|-------------|------|
| demuxerLoop | 11565 | 解封装循环，从Source读取数据，按轨道分发到BQ |
| media_codec(音频) | 11553/11565 | 音频解码，从输入BQ取数据解码后写入输出BQ |
| VideoDecoderAdapter | 11553/11556 | 视频解码适配，调用codec_server硬解 |
| RenderLoop | 11555 | 视频渲染循环，等待解码帧后送显 |
| audiosink | 11565 | 音频输出，从BQ取解码数据写入AudioRenderer |

### 3.2 Buffer流转详解

**音频通路**：
```
demuxerLoop(11565)
  → RequestBuffer(BQ:8) 获取空AVBuffer
  → PushBuffer(BQ:8)   写入ES数据
  
media_codec(音频)
  → 从BQ:8取输入Buffer
  → audioffmpegDecoderPlugin解码
  → QueueInputBuffer → QueueOutputBuffer
  → RequestBuffer(BQ:30) 获取空AVBuffer
  → PushBuffer(BQ:30)  写入PCM数据

audiosink
  → AcquireBuffer(BQ:30) 取PCM数据
  → audioserversinkplugin → AudioRenderer::Write()  ← 阻塞写入
  → ReleaseBuffer(BQ:30) 释放Buffer
```

**视频通路**：
```
demuxerLoop(11565)
  → RequestBuffer(BQ:4) 获取空AVBuffer
  → PushBuffer(BQ:4)   写入视频ES数据

VideoDecoderAdapter
  → AttachBuffer(BQ:4)
  → codec_server 硬件解码
  → OnOutputBufferAvailable 回调

RenderLoop(11555)
  → notify_all 唤醒
  → Surface::ReleaseOutputBuffer() 送显
```

### 3.3 BufferQueue容量配置

| BQ | 容量 | 用途 |
|----|------|------|
| BQ:8 | 8个Buffer | Demuxer → AudioDecoder 音频ES数据 |
| BQ:4 | 4个Buffer | Demuxer → VideoDecoder 视频ES数据 |
| BQ:30 | 30个Buffer | AudioDecoder → AudioSink 音频PCM数据 |
| BufferPool:4 | 4个Buffer | codec_server 视频解码Buffer池 |

## 四、Source与Demuxer初始化

### 4.1 插件注册

```
PluginManager::RegisterPlugins()
  → 循环组装支持 InputFormat 的 plugin
  → 更新 g_pluginInputFormat（pluginName ↔ AVInputFormat映射）
  → Register::AddPlugin()：注册 creator + Sniff 函数
```

### 4.2 Source初始化

```
Source::SetSource(MediaSource)
  → FindPlugin()：根据支持的协议选择插件
  → PluginManager::CreatePlugin() → SourcePlugin
  → SourcePlugin::SetSource()

Source::Start()
  → Pull模式：Activate() 设置pullData回调
  → Push模式：ReadLoop() 启动数据读取循环
```

### 4.3 Demuxer初始化

```
MediaDemuxer::SetDataSource()
  → DataPacker::Start()
  → ActivatePullMode()/ActivatePushMode()：初始化数据读取回调
  → InitTypeFinder()：
    → TypeFinder::FindMediaType()
    → TypeFinder::SniffMediaType()
    → PluginManager::Sniffer()：循环嗅探比较confidence
    → DemuxerPlugin::Sniff() → ffmpeg::read_probe()
    → 返回 pluginName（嗅探失败则根据uri后缀GuessMediaType）
  → InitPlugin()：
    → PluginManager::CreatePlugin() → DemuxerPlugin
    → DemuxerPlugin::SetDataSource(dataSourceImpl)
    → InitAVFormatContext() + AllocAVIOContext()
    → 设置AVReadPacket/AVWritePacket/AVSeek回调
```

### 4.4 数据读取

```
DemuxerPlugin::Start()
  → ffmpeg::av_read_frame()
  → ffmpeg内部调用 AVReadPacket()
  → DataSourceImpl::ReadAt()：
    - Push模式：直接从dataPacker_取数据
    - Pull模式：Source::PullData() → dataPacker_
  → 解封装后按trackId选择对应BufferQueue
  → BufferQueueProducer::RequestBuffer() 获取AVBuffer
  → 拷贝pkt数据到AVBuffer → PushBuffer()
```

## 五、音视频同步

音视频同步由 **MediaSyncManager** 管理：

| 同步方式 | 说明 |
|---------|------|
| 音频主时钟 | 以音频播放进度为基准，视频追音频 |
| 视频帧率控制 | RenderLoop按帧率定时送显 |
| 同步修正 | 视频帧过早则延迟渲染，过晚则丢帧追赶 |

## 知识关联

- [[architecture]] - 架构总览
- [[player-lifecycle]] - 播放器生命周期
- [[seek-architecture]] - Seek架构
- [[pipeline-filter-chain]] - Filter链实体详情
- [[demuxer-filter]] - DemuxerFilter详情
- [[media-demuxer]] - MediaDemuxer详情
- [[source-demuxer-init-flow]] - Source/Demuxer初始化流程
- [[thread-model-buffer-flow]] - 线程模型详情
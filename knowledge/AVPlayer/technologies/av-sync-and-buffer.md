# 音视频同步与缓冲区管理

> A/V 同步机制、BufferQueue 数据流、线程模型。

## 一、音视频同步机制

### MediaSyncManager

**音视频同步管理器**，协调音频和视频的渲染节奏。

| 同步方式 | 说明 |
|---------|------|
| 音频主时钟 | 以音频播放进度为基准（默认） |
| 视频帧率控制 | RenderLoop 按帧率定时送显 |
| 同步修正 | 视频过早则延迟，过晚则丢帧追赶 |

### 同步策略切换

- 音频暂停或不可用时切换同步策略
- Seek 后等待 A/V 同步再恢复

## 二、LPP 硬件同步

### LppSyncManager

**硬件 A/V 同步管理器**，基于硬件时间戳的精准同步。

| 特性 | 说明 |
|------|------|
| anchorPts / anchorClock | 音频锚点时间戳与硬件时钟 |
| UpdateTimeAnchor | 音频渲染器更新锚点 |
| HDI 调用 | 视频请求渲染时间通过 HDI 硬件调度 |

### LPP 硬件同步流程

```
1. 音频渲染器写入数据 → 更新时间锚点 (anchorPts, anchorClock)
2. LppAudioRenderAdapter → HandleAnchorUpdateEvent
3. LppSyncManager.UpdateTimeAnchor() 记录锚点
4. 视频流请求渲染时间 → LppSyncManager 基于硬件时钟计算
5. LppSyncManagerAdapter → HDI 接口硬件调度渲染
6. 视频帧在精确计算的时间渲染
```

## 三、屏幕录制 A/V 同步算法

### 算法流程

```
1. 计算 timeWindow = videoFirstFramePts - audioFirstFramePts
2. 视频早于音频 (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS)
   → 填充静音数据，等待音频
3. 音频早于视频 (timeWindow >= AUDIO_INTERVAL_IN_NS)
   → 丢弃多余音频数据
4. 同步范围内
   → 正常处理音频数据并混合
```

| 参数 | 说明 |
|------|------|
| firstAudioFramePts_ | 首帧音频 PTS（atomic） |
| firstVideoFramePts_ | 首帧视频 PTS（atomic） |
| NEG_AUDIO_INTERVAL_IN_NS | 视频早于音频容忍阈值 |
| AUDIO_INTERVAL_IN_NS | 音频早于视频容忍阈值 |

## 四、BufferQueue 数据流

### 生产者-消费者模型

| 操作 | 说明 |
|------|------|
| RequestBuffer | Producer 获取空 AVBuffer |
| PushBuffer | Producer 写入数据后推送 |
| AcquireBuffer | Consumer 获取数据 AVBuffer |
| ReleaseBuffer | Consumer 消费后释放 |

### BufferQueue 容量配置

| BQ | 容量 | 用途 |
|----|------|------|
| 音频输入 BQ | 8 | Demuxer → AudioDecoder |
| 视频输入 BQ | 4 | Demuxer → VideoDecoder |
| 音频输出 BQ | 30 | AudioDecoder → AudioSink |

### AVBuffer

| 属性 | 说明 |
|------|------|
| data | 帧数据 |
| pts | 显示时间戳 |
| flags | 标志位（关键帧/EOS 等） |

## 五、线程模型与数据流转

### 三线程模型

```
[Demuxer 线程]
  av_read_frame() → SourcePlugin 读取压缩数据
  → DemuxerPlugin 按 trackId 选择 BufferQueue
  → BufferQueueProducer.RequestBuffer() → AVBuffer
  → 拷贝 pkt 数据 → PushBuffer()

[Decoder 线程]
  从上游 BufferQueueConsumer 取 AVBuffer
  → 解码（AudioDecoderFilter / DecoderSurfaceFilter）
  → 解码数据写入下游 BufferQueue

[Sink 线程]
  从解码输出 BufferQueueConsumer 取 AVBuffer
  → AudioSink 渲染音频 / VideoSink 渲染视频
  → MediaSyncManager 协调 A/V 同步
```

## 知识关联

- [[architecture]] - 架构总览
- [[engine-layer-entities]] - 引擎层实体
- [[engine-factory-and-selection]] - LPP 引擎
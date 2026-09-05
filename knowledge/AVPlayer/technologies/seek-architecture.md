# Seek完整架构

> Seek操作的分层架构、不同格式通路、去重合并机制与整改历程。

## 一、Seek总体架构

Seek 操作在播放器框架中跨越 **三层**：PlayerServer → HiPlayerImpl → Pipeline：

```
应用 → PlayerClient::SeekTo(timeMs, mode)
  → IPC → PlayerServer::SeekTo()
  → TaskMgr::Enqueue(HandleSeek)  ← 异步任务
  → HiPlayerImpl::SeekTo()
  → Pipeline::SendCommand(SEEK)  ← 通过Pipeline统一控制
  → 各Filter依次执行Seek
```

### 核心设计原则

**通过Pipeline统一操作**：HiPlayerImpl 不直接操作具体 Filter，而是通过 Pipeline 发送 SEEK 命令，由 Pipeline 按链路依次传递给每个 Filter。这避免了分支复杂、维护成本高的问题。

## 二、Seek状态流转

Seek 在不同播放状态下的行为：

| 起始状态 | Seek后状态 | 说明 |
|---------|-----------|------|
| STARTED | STARTED | Seek完成后继续播放 |
| PAUSED | PAUSED | Seek完成后保持暂停 |
| PREPARED | PREPARED | 准备完成后Seek到指定位置 |
| COMPLETE | Flushed → Seeked → STARTED | 播放结束Seek会重新起播 |

### Seek执行阶段

```
1. Flush阶段：清空所有Filter的缓冲区
   DemuxerFilter → AudioDecoderFilter → AudioSinkFilter
                  → DecoderSurfaceFilter → VideoSink

2. Seek阶段：定位到目标时间点
   Source::SeekToTime() → HTTP/HLS: SeekToTime
   DemuxerPlugin::SeekTo() → ffmpeg: SeekToPos

3. Resume阶段：恢复数据流
   DemuxerFilter::Resume() → 重新读取数据
   各Decoder/Sink Filter::Resume()
```

## 三、不同格式的Seek通路

### 3.1 本地文件Seek

```
HiPlayer → DemuxerFilter → MediaDemuxer → DemuxerPlugin(ffmpeg)
  → ffmpegDemuxerPlugin::SeekToPos()  ← 直接按偏移量定位
  → AVReadPacket() 从新位置读取数据
```

### 3.2 HTTP流Seek

```
HiPlayer → DemuxerFilter → MediaDemuxer → Source → HttpSourcePlugin
  → Source::SeekToTime()
  → HttpSourcePlugin::SeekTo()  ← HTTP Range请求
  → HLS: HLSDownloader 重新请求对应分片
```

### 3.3 Push模式Seek

Push模式（如直播流）的Seek较为特殊：
- 依赖Source的ReadLoop暂停和恢复
- Demuxer的DataPacker需要清空缓存
- 部分Push模式不支持Seek（UNSEEKABLE）

## 四、Seek去重合并机制

连续快速Seek时（如拖拽进度条），通过 **去重合并** 避免无效Seek：

### 4.1 去重策略

| 策略 | 说明 |
|------|------|
| 最新请求优先 | 队列中已有Seek任务时，新请求替换旧任务（仅保留最新目标时间） |
| TwoPhaseTaskItem | Prepare阶段记录目标时间，Execute阶段执行，中间可被新请求覆盖 |
| 拖拽代理 | DraggingPlayerAgent 管理拖拽场景的连续Seek，仅在松手时执行最终Seek |

### 4.2 SeekAgent

SeekAgent 是 HiPlayerImpl 内部的 Seek 管理器：

| 方法 | 说明 |
|------|------|
| SeekTo() | 发起Seek请求 |
| CancelSeek() | 取消正在进行的Seek |
| IsSeeking() | 是否正在Seek |

### 4.3 DraggingPlayerAgent

拖拽场景的特殊处理：

| 代理类 | 行为 |
|--------|------|
| SeekContinuousDelegator | 连续拖拽，持续Seek到最新位置 |
| SeekClosestDelegator | 精准拖拽，Seek到最近关键帧 |
| DraggingDelegatorFactory | 工厂模式创建对应的拖拽代理 |

## 五、SeekClosest算法

SeekClosest 模式下 Seek 到最近关键帧的算法：

1. DemuxerPlugin::SeekTo() 跳到目标时间点
2. 读取该位置附近的帧，找到最近的关键帧
3. 如果目标位置不是关键帧：
   - 向前找最近的关键帧
   - 解码到目标位置（可能需要解码几帧B/P帧）
4. 返回实际Seek到的时间点

## 六、Seek整改历程

### 6.1 原有问题

| 问题 | 原因 |
|------|------|
| Pause后Seek再起播漏数据 | Seek时没有Flush操作，存在残留数据 |
| 进度条跳变 | 残留数据导致pause不会立即停，起播后进度回跳 |
| 概率性花屏 | 解码器内部缓存未清空，旧帧混入新帧 |
| 来回Seek后音画不同步 | 各Filter Flush不一致，导致音视频数据不齐 |

### 6.2 整改方案

**核心思路**：通过Pipeline统一控制所有节点的Flush和Resume

| 改动点 | 内容 |
|--------|------|
| Pipeline统一控制 | 不再由HiPlayer直接操作Filter，改为Pipeline::SendCommand统一分发 |
| Flush操作 | Seek前所有Filter和BufferQueue必须Flush |
| ffmpeg缓存清理 | DemuxerPlugin内部ffmpeg缓存需要同步清理 |
| BufferQueue清理 | 每个BQ的Flush接口清空所有未消费Buffer |
| Pause/Resume顺序 | demuxer先Pause，解码器后Pause；Resume则反向 |

### 6.3 Pipeline Pause逻辑

Seek整改中明确了各节点的Pause行为：

| 节点 | Pause行为 | 说明 |
|------|----------|------|
| DemuxerFilter | 加Pause | 停止读取数据 |
| media_codec | 无Pause | 解码器本身无Pause接口 |
| AudioSink | Pause无问题 | 保证音频不再输出 |
| VideoDecoderAdapter | 加Pause | 拦截送显，Flush时调用ResetSyncInfo |
| VideoSink | 加Pause | 调用ResetSyncInfo |

### 6.4 Pipeline Flush逻辑

| 组件 | Flush行为 |
|------|----------|
| DemuxerFilter | 添加BQ的flush |
| BQ(音频/视频ES) | 添加BQ的flush |
| AudioDecoderFilter → AudioSinkFilter BQ | 添加BQ的flush |
| VideoDecoderAdapter | 加Flush |
| indexs | 添加indexs的清空 |
| VideoSink | 加Flush |

### 6.5 关键技术点总结

1. **demuxer、解码器的Pause/Resume接口调用顺序**必须严格按层级执行
2. **ffmpeg缓存清理**：Seek时必须清理ffmpeg内部缓存
3. **BufferQueue清理**：每个BQ必须清空，否则残留数据导致各种异常

## 知识关联

- [[architecture]] - 架构总览
- [[player-lifecycle]] - 播放器生命周期
- [[pipeline-architecture]] - Pipeline架构
- [[seek-agent]] - SeekAgent详情
- [[seek-dedup-merge]] - Seek去重合并详情
- [[seek-closest-algorithm]] - SeekClosest算法详情
- [[seek-remediation]] - Seek整改详情

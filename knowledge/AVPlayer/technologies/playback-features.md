# 播放控制与特性

> Seek、音量、循环、速率、回调、Surface、字幕、DRM 等播放功能。

## 一、Seek 架构

### Seek 模式

| 模式 | 行为 | 适用场景 |
|------|------|---------|
| SEEK_PREVIOUS_SYNC | 跳到目标前最近关键帧 | 快退 |
| SEEK_NEXT_SYNC | 跳到目标后最近关键帧 | 快进 |
| SEEK_CLOSEST_SYNC | 跳到最近关键帧 | 通用 |
| SEEK_CLOSEST | 精准帧（SeekAgent 逐帧比较） | 缩略图/精准定位 |
| SEEK_CONTINOUS | 连续拖拽（无去重、无完成事件） | 进度条拖拽 |

### Seek 分层架构

```
HiPlayerImpl (入口)
  → SeekAgent (去重/合并)
  → Pipeline (统一 Pause/Flush/Seek/Resume)
  → Demuxer/Decoder/Sink Filter
```

### Seek 去重合并

| 变量 | 说明 |
|------|------|
| mCurrentPosition | 最新请求位置 |
| mSeekPosition | 当前执行位置 |
| isSeeking_ | 是否正在执行 Seek |

**流程**：新 Seek 到达 → 与 mSeekPosition 比较 → 相同则忽略 → 不同则替换 → 执行完毕后检查有无待处理请求

### SEEK_CLOSEST 精准帧算法

1. SeekAgent::Seek → 转换为 PTS（seekTargetPts_）
2. Demuxer::SeekTo(SEEK_CLOSEST_INNER) → 定位到目标附近
3. 注册 Audio/Video BufferFilledListener
4. Demuxer ResumeForSeek → 恢复数据读取
5. OnAudioBufferFilled/OnVideoBufferFilled 检查 Buffer PTS
6. buffer->pts_ >= seekTargetPts_ 或 EOS → 标记该轨道到达目标
7. 所有轨道到达 → 通知 Seek 完成

### 连续 Seek（拖拽）

- **SeekContinous(mSeconds, batchNo)**：batchNo 标识一次拖拽会话
- **ExitSeekContinous**：用户释放 → 执行最终 Seek
- **PlayerServerTaskMgr**：自动替换旧任务

### Seek 整改

历史问题 → 修复方案：

| 问题 | 修复 |
|------|------|
| 控制流不一致（HiPlayer 绕过 Pipeline） | Pipeline 统一控制 Seek 流 |
| 缺少 Flush 导致残留数据 | Pause → Flush → Seek → Resume |
| 概率性花屏 | ffmpeg 缓存清理 + BufferQueue 清理 |
| 追帧与 A/V 不同步 | 统一 Seek 后 A/V 同步恢复 |

## 二、音量控制

| API | 说明 | 范围 |
|-----|------|------|
| SetVolume(left, right) | 双声道音量 | [0.0, 1.0] |
| SetVolumeMode(mode) | 音量模式 | — |
| SetLoudnessGain(gain) | 响度增益 | — |
| SetMediaMuted(mediaType, isMuted) | 按媒体类型静音 | audio/video 独立 |

**链路**：App → PlayerServer::SetVolume → 校验 → ConfigInfo 保存 + IPlayerEngine::SetVolume 应用

**C API 链路**：OH_AVPlayer_SetVolume → PlayerImpl::SetVolume → HiPlayerImpl::SetVolume / SetMediaMuted

## 三、循环模式

- **SetLooping(loop)**：true 循环，false 单次
- **存储**：ConfigInfo.looping（atomic\<bool\>）
- **触发**：HandleEos 时检查 looping → true 则重新 Play

## 四、播放速率控制

| API | 说明 |
|-----|------|
| SetPlaybackSpeed(PlaybackRateMode) | 枚举速率模式 |
| SetPlaybackRate(float) | 浮点速率值 |

**链路**：App → PlayerServer → TaskMgr::SpeedTask（RATE_CHANGE 类型，替换旧任务）→ HandleSetPlaybackSpeed/Rate → IPlayerEngine

## 五、回调机制

### 双向 IPC 回调链

```
PlayerServer::OnInfo
  → PlayerListenerCallback::OnInfo (桥接)
  → PlayerListenerProxy::OnInfo (IPC 发送)
  → PlayerListenerStub::OnInfo (IPC 接收)
  → PlayerCallback::OnInfo (应用层)
```

### 事件类型

| 事件 | 说明 |
|------|------|
| STATE_CHANGE | 状态变更 |
| SEEKDONE | Seek 完成 |
| INFO_TYPE_EOS | 播放结束 |
| INTERRUPT_EVENT | 音频中断 |
| POSITION_UPDATE | 位置更新 |
| BUFFERING_UPDATE | 缓冲进度 |

### 消息处理

- PlayerServer 通过 OnInfo(PlayerOnInfoType) 接收引擎消息
- BaseState::OnMessageReceived 分发到状态类
- InnerOnInfo：先状态处理，再回调通知客户端

## 六、媒体源设置

| 类型 | 方法 | 说明 |
|------|------|------|
| URL | SetSource(url) | HTTP/HTTPS/File/FD 协议 |
| FD | SetSource(fd, offset, size) | 文件描述符 + 偏移范围 |
| DataSource | SetSource(dataSrc) | 自定义 IMediaDataSource |
| AVMediaSource | SetMediaSource(source, strategy) | 媒体描述 + 播放策略 |

**URL 源**：StreamCacheManager/DownloadedCacheManager 缓存管理
**Custom 源**：IMediaDataSource 回调按需提供数据（加密场景）

## 七、视频 Surface 管理

**IPC 链路**：PlayerClient::SetVideoSurface → PlayerServiceProxy（序列化 Surface）→ IPC → PlayerServiceStub（反序列化）→ PlayerServer → IPlayerEngine

**内存恢复**：RecoverConfigInfo.surface 保存 Surface 引用

## 八、字幕轨道管理

| API | 说明 |
|-----|------|
| AddSubSource(url/fd) | 添加字幕源 |
| GetSubtitleTrackInfo | 获取字幕轨道信息 |
| SelectTrack / DeselectTrack | 选择/取消轨道（PlayerSwitchMode） |

## 九、DRM 集成

- **SetDecryptConfig**：传递 MediaKeySession 代理 + SVP（安全视频路径）标志
- **SVP 标志**：指示是否需要安全视频路径
- **IPC 链路**：PlayerClient → PlayerServiceProxy::SetDecryptConfig → IPC → Stub → PlayerServer → IPlayerEngine

## 十、视频缩放与音频效果

| 功能 | 枚举/接口 | 说明 |
|------|----------|------|
| 视频缩放 | VideoScalingMode | 等比缩放/拉伸填充/裁剪填充 |
| 音频效果 | AudioEffectMode | 通过 audioSink_ 配置 |

## 十一、媒体描述查询

| API | 返回 |
|-----|------|
| GetVideoWidth/Height | 视频尺寸 |
| GetCurrentTime | 当前播放位置 |
| GetDuration | 总时长 |
| GetVideoTrackInfo | 视频轨道信息（Format 对象）|
| GetAudioTrackInfo | 音频轨道信息 |
| GetSubtitleTrackInfo | 字幕轨道信息 |
| GetCurrentTrack | 当前轨道 |

## 十二、Native API 生命周期

| 状态 | 枚举值 | 可达转换 |
|------|--------|---------|
| Idle | PLAYER_IDLE | → Initialized |
| Initialized | PLAYER_INITIALIZED | → Preparing |
| Preparing | — | → Prepared |
| Prepared | PLAYER_PREPARED | → Playing |
| Playing | PLAYER_STARTED | → Paused/Stopped/Completed |
| Paused | PLAYER_PAUSED | → Playing/Stopped |
| Stopped | PLAYER_STOPPED | → Idle(Reset) |
| Completed | PLAYER_PLAYBACK_COMPLETE | → Playing/Stopped |
| Error | PLAYER_STATE_ERROR | → Released |
| Released | PLAYER_RELEASED | 终态 |

## 知识关联

- [[architecture]] - 架构总览
- [[engine-layer-entities]] - 引擎层实体
- [[service-layer]] - 服务层实体
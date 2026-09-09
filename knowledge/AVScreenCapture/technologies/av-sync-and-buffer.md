# 音视频同步与缓冲区管理

> 屏幕录制的 A/V 同步算法、音频混音机制、视频/音频缓冲区管理、数据读取流程。

## 一、屏幕录制 A/V 同步算法

A/V 同步在 `AudioDataSource` 和 `AudioDataSourceGeneric` 中实现，用于 CAPTURE_FILE 模式下音频与视频首帧对齐。

### 1.1 算法流程

```
SetVideoFirstFramePts(firstFramePts)
  → firstVideoFramePts_ 存储

ReadAt()
  → ReadWriteAudioBufferMix()
    → 若 firstAudioFramePts_ == -1（初次同步）：
      → GetFirstAudioTime() 获取音频首帧时间戳
      → timeWindow = firstVideoFramePts_ - audioTime
      → VideoAudioSyncMixMode(timeWindow, inner, mic)
```

### 1.2 同步判定逻辑

```
timeWindow = firstVideoFramePts_ - audioTime

├── timeWindow <= NEG_AUDIO_INTERVAL_IN_NS（视频早于音频）
│   → SetAudioFirstFramePts(firstVideoFramePts_)
│   → LostFrameNum() 填充静音帧，使音频对齐到视频时间戳
│
├── timeWindow >= AUDIO_INTERVAL_IN_NS（视频晚于音频）
│   → micCapture_->DropBufferUntil(firstVideoFramePts_)
│   → innerCapture_->DropBufferUntil(firstVideoFramePts_)
│   → 丢弃早于视频首帧的音频数据
│   → SetAudioFirstFramePts(firstVideoFramePts_)
│
└── NEG_AUDIO_INTERVAL_IN_NS < timeWindow < AUDIO_INTERVAL_IN_NS（同步范围内）
    → 正常混合输出
```

### 1.3 参数表

| 参数 | 值 | 说明 |
|------|-----|------|
| `firstAudioFramePts_` | 初始 -1 | 音频首帧 PTS，初次同步后设置 |
| `firstVideoFramePts_` | atomic, 初始 -1 | 视频首帧 PTS，由 Recorder 通过 SetVideoFirstFramePts 设置 |
| `NEG_AUDIO_INTERVAL_IN_NS` | -21333334 | 负同步阈值（约 -21.3ms） |
| `AUDIO_INTERVAL_IN_NS` | 21333334 | 正同步阈值（约 21.3ms） |
| `MAX_INNER_AUDIO_TIMEOUT_IN_NS` | 2000000000 | 内录等待超时 2s |
| `AUDIO_MIC_TOO_CLOSE_LIMIT_IN_NS` | 10000000 | 麦克风/内录时间差限制 10ms |
| `MAX_MIC_BEFORE_INNER_TIME_IN_NS` | 40000000 | 麦克风超前内录限制 40ms |

## 二、音频混音机制

### 2.1 混音模式

```cpp
enum class AVScreenCaptureMixMode : int32_t {
    MIX_MODE = 0,     // 混音模式：内录 + 麦克风
    MIC_MODE = 1,     // 仅麦克风
    INNER_MODE = 2,   // 仅内录
    INVALID_MODE = 3,
};
```

| 模式 | 数据来源 | 使用场景 |
|------|---------|---------|
| MIX_MODE | innerCapture + micCapture | 同时录制内录和麦克风 |
| MIC_MODE | micCapture | 仅录制麦克风 |
| INNER_MODE | innerCapture | 仅录制系统播放音 |

### 2.2 混音缓冲类型

```cpp
enum class AVScreenCaptureMixBufferType : int32_t {
    MIX = 0,     // 混合数据
    MIC = 1,     // 仅麦克风数据
    INNER = 2,   // 仅内录数据
    SILENT = 3,  // 静音帧（填充对齐用）
    INVALID = 4,
};
```

### 2.3 InnerMicAudioSync（内录/麦克风同步）

```
InnerMicAudioSync(innerAudioBuffer, micAudioBuffer)
  timeWindow = mic.timestamp - inner.timestamp

  ├── timeWindow <= NEG_AUDIO_INTERVAL_IN_NS（麦克风早于内录）
  │   → micCapture_->DropBufferUntil(inner.timestamp)
  │   → 丢弃过早的麦克风数据
  │
  ├── NEG_AUDIO_INTERVAL_IN_NS < timeWindow < AUDIO_INTERVAL_IN_NS（同步范围内）
  │   → WriteMixAudio(inner, mic) → MixAudio() 混合
  │
  └── timeWindow >= AUDIO_INTERVAL_IN_NS（麦克风晚于内录）
      → WriteInnerAudio(inner) → 仅输出内录数据
```

### 2.4 VideoAudioSyncMixMode（音视频同步混音模式）

在 CAPTURE_FILE 模式下，当存在视频时进行 A/V 同步：

```
VideoAudioSyncMixMode(timeWindow, inner, mic)
  ├── timeWindow <= NEG_AUDIO_INTERVAL_IN_NS → 填充静音帧
  ├── timeWindow >= AUDIO_INTERVAL_IN_NS → 丢弃音频数据
  └── 正常范围 → ReadWriteAudioBufferMixCore() 正常混合
```

### 2.5 AudioDataSourceGeneric 混音策略

```cpp
enum class AudioCombinePolicy : int32_t {
    PASSTHROUGH,  // 透传模式
    MIX_ALL,      // 全混音模式
};
```

CAPTURE_FILE 模式使用 `MIX_ALL` 策略，通过 `CaptureSlot` 管理多个音频源的状态（INACTIVE/UNSTABLE/STABLE）。

## 三、视频缓冲管理

### 3.1 Surface 缓冲消费者模型

```
虚拟屏幕 Surface（Producer）
  → SurfaceBuffer 入队
  → Consumer（ScreenCapBufferConsumerListener）
  → OnBufferAvailable() → 消息队列
  → SurfaceBufferThreadRun → OnBufferAvailableAction
  → AcquireBuffer → 入 availBuffers_ 队列
  → ProcessVideoBufferCallBack → OnVideoBufferAvailable(true)
  → 应用 AcquireVideoBuffer → 从 availBuffers_ 取出
  → 应用 ReleaseVideoBuffer → ReleaseBuffer 回还给 Consumer
```

### 3.2 独立线程处理

`ScreenCapBufferConsumerListener` 维护独立线程 `SurfaceBufferThreadRun` 处理消息队列：

```cpp
enum class SCBufferMessageType {
    EXIT,       // 退出线程
    GET_BUFFER, // 获取缓冲
};

while (true) {
    wait(messageQueueSCB_.not_empty);
    message = messageQueueSCB_.front();
    // 消息队列超过 MAX_MESSAGE_QUEUE_SIZE(5) 时丢弃旧 GET_BUFFER
    if (message.type == EXIT) break;
    if (message.type == GET_BUFFER) OnBufferAvailableAction();
}
```

### 3.3 缓冲队列参数

| 参数 | 值 | 说明 |
|------|-----|------|
| `MAX_BUFFER_SIZE` | 3 | 视频缓冲队列最大容量，超限丢帧 |
| `MAX_MESSAGE_QUEUE_SIZE` | 5 | 消息队列最大容量，超限丢弃旧消息 |
| `OPERATION_TIMEOUT_IN_MS` | 1000 | AcquireVideoBuffer 等待超时 |

### 3.4 丢帧策略

```cpp
void OnBufferAvailableAction() {
    // ...
    if (availBuffers_.size() > MAX_BUFFER_SIZE) {
        // 消费过慢，丢弃最早的视频帧
        consumer_->ReleaseBuffer(buffer, -1);
        return;
    }
    availBuffers_.push(std::make_unique<SurfaceBufferEntry>(...));
}
```

### 3.5 AcquireVideoBuffer / ReleaseVideoBuffer

```cpp
int32_t AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage) {
    // 等待 availBuffers_ 非空（超时 1000ms）
    bufferCond_.wait_for(lock, 1000ms, [] { return !availBuffers_.empty(); });
    surfaceBuffer = availBuffers_.front()->buffer;
    fence = availBuffers_.front()->flushFence;
    // 注意：Acquire 后不 pop，Release 时才 pop
}

int32_t ReleaseVideoBuffer() {
    consumer_->ReleaseBuffer(availBuffers_.front()->buffer, -1);
    availBuffers_.pop();
}
```

## 四、音频缓冲管理

### 4.1 AudioCapturerWrapper 状态机

```cpp
enum AudioCapturerWrapperState : int32_t {
    CAPTURER_UNKNOWN = -1,
    CAPTURER_RECORDING,   // 采集中
    CAPTURER_PAUSED,       // 暂停
    CAPTURER_STOPPING,     // 停止中
    CAPTURER_STOPED,       // 已停止
    CAPTURER_RELEASED,     // 已释放
};
```

状态转换：`CAPTURER_UNKNOWN(-1) → CAPTURER_RECORDING → CAPTURER_PAUSED → CAPTURER_STOPPING → CAPTURER_STOPED → CAPTURER_RELEASED`

通过 `IsRecording()`（== CAPTURER_RECORDING）和 `IsStop()`（>= CAPTURER_STOPPING）判断采集状态。

### 4.2 AudioCapturerWrapper + CacheBuffer

```
AudioCapturer::ReadCallback
  → AudioCapturerReadCallbackImpl::OnReadData(length)
  → AudioCapturerWrapper::OnReadData(length)
  → AcquireBuffer → CacheBuffer 入队 availBuffers_
  → NotifyBufferAvailable → OnBufferAvailable(type)
```

### 4.3 CacheBuffer 结构

```cpp
class CacheBuffer {
    int32_t length;           // 数据长度
    int64_t timestamp;        // 时间戳（ns）
    AudioCaptureSourceType sourcetype;  // 音频源类型
    const uint8_t *Data() const;        // 数据指针
    bool WriteTo(AVBuffer/AudioBuffer);  // 写入目标缓冲
};
```

### 4.4 AcquireAudioBuffer / ReleaseAudioBuffer

```cpp
int32_t AcquireAudioBuffer(cacheBuf) {
    // 从 availBuffers_ 队首取出 CacheBuffer
    // 不立即 pop，Release 时才 pop
}
int32_t ReleaseAudioBuffer() {
    availBuffers_.pop_front();
    bufferCond_.notify_one();
}
```

### 4.5 缓冲对齐

| 方法 | 说明 |
|------|------|
| `UseUpAllLeftBufferUntil(audioTime)` | 消费到指定时间戳之前的所有缓冲 |
| `DropBufferUntil(audioTime)` | 丢弃到指定时间戳之前的所有缓冲 |

用于 A/V 同步时丢弃/消费不匹配的音频数据。

## 五、AudioDataSource 数据读取

```cpp
AudioDataSourceReadAtActionState ReadAt(buffer, length) {
    switch (type_) {
        case MIX_MODE:   return ReadAtMixMode();    // 内录+麦克风混音
        case MIC_MODE:   return ReadAtMicMode();    // 仅麦克风
        case INNER_MODE: return ReadAtInnerMode();  // 仅内录
    }
}
```

| 返回状态 | 说明 |
|----------|------|
| OK | 数据已写入 buffer |
| RETRY_SKIP | 重试并跳过日志 |
| RETRY_IN_INTERVAL | 等待麦克风同步 |
| SKIP_WITHOUT_LOG | 跳过且不记录日志 |
| INVALID | 无效状态 |

## 六、数据模式对比

| 维度 | BUFFER_MODE | SUFFACE_MODE | FILE_MODE |
|------|-------------|--------------|-----------|
| 视频获取 | AcquireVideoBuffer | Surface 回调 | Recorder 编码 |
| 音频获取 | AcquireAudioBuffer | 不适用 | AudioDataSource |
| A/V 同步 | 应用自行处理 | 不适用 | AudioDataSource 内部同步 |
| 缓冲管理 | ScreenCapBufferConsumerListener | Surface 直接传递 | Recorder 管理 |
| 编码 | 无（原始帧） | 无（原始帧） | Recorder 编码封装 |

## 知识关联

- [[capture-lifecycle]] - 录屏完整生命周期
- [[capture-features]] - 录制控制特性
- [[design-patterns]] - 设计模式（消费者模型）
- [[flows]] - 关键流程详解（视频缓冲获取、音频采集启动）

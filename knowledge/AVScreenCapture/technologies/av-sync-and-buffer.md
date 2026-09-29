# 音视频同步与缓冲区管理

> 屏幕录制的 A/V 同步算法、音频混音机制、视频/音频缓冲区管理、数据读取流程。

## 一、A/V 同步算法

A/V 同步在 AudioDataSource 中实现，用于 CAPTURE_FILE 模式下音频与视频首帧对齐。

### 1.1 同步流程

1. Recorder 通过 SetVideoFirstFramePts 设置视频首帧时间戳
2. ReadAt 时若音频首帧未设置：获取音频首帧时间戳，计算 timeWindow = 视频首帧 - 音频首帧
3. 按 timeWindow 判定对齐策略

### 1.2 同步判定逻辑

| 条件 | 含义 | 处理 |
|------|------|------|
| timeWindow ≤ 负阈值 | 视频早于音频 | 填充静音帧，使音频对齐到视频时间戳 |
| timeWindow ≥ 正阈值 | 视频晚于音频 | 丢弃早于视频首帧的音频数据 |
| 阈值范围内 | 同步 | 正常混合输出 |

> 阈值为内部调优参数，用于判定视频领先/落后音频的程度；超阈值则填充静音帧或丢弃音频。

## 二、音频混音机制

### 2.1 混音模式

| 模式 | 值 | 数据来源 | 使用场景 |
|------|---|---------|---------|
| MIX_MODE | 0 | 内录 + 麦克风 | 同时录制内录和麦克风 |
| MIC_MODE | 1 | 仅麦克风 | 仅录制麦克风 |
| INNER_MODE | 2 | 仅内录 | 仅录制系统播放音 |
| INVALID_MODE | 3 | 无效 | 无效 |

### 2.2 混音缓冲类型

| 类型 | 值 | 说明 |
|------|---|------|
| MIX | 0 | 混合数据 |
| MIC | 1 | 仅麦克风数据 |
| INNER | 2 | 仅内录数据 |
| SILENT | 3 | 静音帧（填充对齐用） |
| INVALID | 4 | 无效 |

### 2.3 内录/麦克风同步（InnerMicAudioSync）

按麦克风与内录时间差判定：麦克风过早则丢弃过早数据；范围内则混合；麦克风过晚则仅输出内录。

### 2.4 音视频同步混音（VideoAudioSyncMixMode）

CAPTURE_FILE 模式存在视频时：视频早于音频填充静音帧；视频晚于音频丢弃音频；范围内正常混合。

### 2.5 混音策略

CAPTURE_FILE 模式使用全混音策略，通过 CaptureSlot 管理多音频源状态（INACTIVE/UNSTABLE/STABLE）。

## 三、视频缓冲管理

### 3.1 Surface 缓冲消费者模型

虚拟屏幕 Surface(Producer) 写入 SurfaceBuffer → Consumer(BufferConsumerListener) 收到就绪回调 → 独立线程获取入队 → 回调应用 → 应用 Acquire/Release 配对。

### 3.2 独立线程处理

BufferConsumerListener 维护独立线程处理消息队列（EXIT/GET_BUFFER）。消息队列有上限，超限丢弃旧消息。

### 3.3 丢帧策略

视频缓冲队列有上限，消费过慢时丢弃最早的帧归还给 Consumer，防止积压。

### 3.4 Acquire/Release 语义

- AcquireVideoBuffer：等待队列非空（带超时），返回队首，不立即弹出
- ReleaseVideoBuffer：归还给 Consumer 并弹出
- Acquire 与 Release 必须严格配对

## 四、音频缓冲管理

### 4.1 AudioCapturerWrapper 状态机

状态转换：UNKNOWN → RECORDING → PAUSED → STOPPING → STOPED → RELEASED。通过 IsRecording/IsStop 判断采集状态。

### 4.2 数据流

AudioCapturer 数据读取回调 → Wrapper → CacheBuffer 入队 → 通知应用缓冲就绪 → 应用 Acquire/Release 配对。

### 4.3 缓冲对齐

- UseUpAllLeftBufferUntil(time)：消费到指定时间戳之前的所有缓冲
- DropBufferUntil(time)：丢弃到指定时间戳之前的所有缓冲

用于 A/V 同步时丢弃/消费不匹配的音频数据。

## 五、AudioDataSource 数据读取

按混音模式分发：MIX_MODE 内录+麦克风混音；MIC_MODE 仅麦克风；INNER_MODE 仅内录。

| 返回状态 | 说明 |
|----------|------|
| OK | 数据已写入 |
| RETRY_SKIP | 重试并跳过日志 |
| RETRY_IN_INTERVAL | 等待麦克风同步 |
| SKIP_WITHOUT_LOG | 跳过且不记录日志 |
| INVALID | 无效状态 |

## 六、数据模式对比

| 维度 | BUFFER_MODE | SURFACE_MODE | FILE_MODE |
|------|-------------|--------------|-----------|
| 视频获取 | AcquireVideoBuffer | Surface 回调 | Recorder 编码 |
| 音频获取 | AcquireAudioBuffer | 不适用 | AudioDataSource |
| A/V 同步 | 应用自行处理 | 不适用 | AudioDataSource 内部同步 |
| 缓冲管理 | BufferConsumerListener | Surface 直接传递 | Recorder 管理 |
| 编码 | 无（原始帧） | 无（原始帧） | Recorder 编码封装 |

## 知识关联

- [capture-lifecycle](capture-lifecycle.md) - 录屏完整生命周期
- [capture-features](capture-features.md) - 录制控制特性
- [design-patterns](design-patterns.md) - 设计模式（消费者模型）
- [flows](flows.md) - 关键流程详解

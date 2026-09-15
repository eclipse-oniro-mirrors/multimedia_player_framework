# 采集实现实体

> 虚拟屏幕、音频采集、缓冲管理、A/V 同步等屏幕录制采集实现层（无独立引擎层，采集逻辑内置于 ScreenCaptureServer）

## 实体概念

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| 虚拟屏幕实体 | ScreenCaptureServer 内置的虚拟屏幕管理方法集 | MakeVirtualScreenMirror 镜像模式；MakeVirtualScreenExtended 扩展模式；CreateVirtualScreen 创建；DestroyVirtualScreen 销毁；ChangeMirrorScreen 切换镜像；InitVirtualScreenOption 初始化选项 | 采集实现 |
| Rosen::ScreenManager | 外部依赖，Rosen 图形框架屏幕管理 | 创建/销毁虚拟屏幕；屏幕镜像/扩展；屏幕旋转；outline 高亮 | 外部依赖 |
| Surface / SurfaceBuffer | 视频帧数据载体 | consumer_ 消费者 Surface；producerSurface_ 生产者 Surface；SurfaceBuffer 帧数据 | 缓冲载体 |
| ScreenCapBufferConsumerListener | 视频缓冲消费者监听，实现 IBufferConsumerListener | 独立线程 SurfaceBufferThreadRun；消息队列（EXIT/GET_BUFFER）；最大缓冲 3 个；OnBufferAvailable 回调；AcquireVideoBuffer/ReleaseVideoBuffer 获取释放 | 缓冲监听 |
| AudioCapturerWrapper | 音频采集封装，封装 AudioStandard::AudioCapturer | CAPTURER_UNKNOWN→CAPTURER_RECORDING→CAPTURER_PAUSED→CAPTURER_STOPPING→CAPTURER_STOPED→CAPTURER_RELEASED 状态机；OnReadData 回调入队；CacheBuffer 缓冲；SetIsInVoIPCall/SetIsMute/UpdateAudioCapturerConfig 控制 | 音频采集封装 |
| AudioCapturerCallbackImpl | 音频中断/状态变化回调 | OnInterrupt 中断事件；OnStateChange 状态变化 | 音频回调 |
| AudioCapturerReadCallbackImpl | 音频数据读取回调 | OnReadData(length) 数据就绪通知；weak_ptr 回持有 AudioCapturerWrapper | 音频回调 |
| AudioDataSource | 混音 + 同步，实现 IAudioDataSource | MIX_MODE/MIC_MODE/INNER_MODE/INVALID_MODE 混音模式；ReadAt 读取；MixAudio 混音；VideoAudioSyncMixMode 视频音频同步；InnerMicAudioSync 内部麦克风同步；Pause/Resume | 混音/同步 |
| CacheBuffer | 音频缓冲区封装 | unique_ptr\<uint8_t[]\> ownedBuf_；WriteTo(AVMemory) 写入内存；WriteTo(AudioBuffer) 写入音频缓冲；Data() 原始数据访问 | 音频缓冲 |
| AudioBuffer | 音频缓冲区结构 | buffer(uint8_t*)；length；timestamp；sourcetype(AudioCaptureSourceType)；析构 free(buffer) | 缓冲结构 |
| IRecorderService | 文件录制复用的 Recorder 引擎接口 | FILE_MODE 下通过 Recorder 引擎录制到文件；复用 AVRecorder 的录制流水线 | 外部引擎接口 |
| VideoPermissionState | 视频权限状态枚举 | START_VIDEO/STOP_VIDEO | 枚举 |
| AVScreenCaptureAvType | 音视频类型枚举 | INVALID_TYPE/AUDIO_TYPE/VIDEO_TYPE/AV_TYPE | 枚举 |
| AVScreenCaptureDataMode | 数据模式枚举 | BUFFER_MODE/SUFFACE_MODE/FILE_MODE | 枚举 |
| StopReason | 停止原因枚举 | NORMAL_STOPPED/RECEIVE_USER_PRIVACY_AUTHORITY_FAILED/POST_START_SCREENCAPTURE_HANDLE_FAILURE/REQUEST_USER_PRIVACY_AUTHORITY_FAILED/STOP_REASON_INVALID | 枚举 |

## 上下文与场景

### 交互流程

**视频采集流程（BUFFER_MODE / SURFACE_MODE）**：

```
ScreenCaptureServer::StartStreamVideoCapture
  → MakeVirtualScreenMirror / MakeVirtualScreenExtended (Rosen::ScreenManager)
  → CreateVirtualScreen(consumer_)
  → ScreenCapBufferConsumerListener::StartBufferThread
  → SurfaceBufferThreadRun 循环 (GET_BUFFER 消息)
  → OnBufferAvailable → ProcessVideoBufferCallBack
  → ScreenCaptureCallBack::OnVideoBufferAvailable
  → 应用 AcquireVideoBuffer / ReleaseVideoBuffer
```

**音频采集流程（BUFFER_MODE）**：

```
ScreenCaptureServer::StartInnerAudioCapture / StartMicAudioCapture
  → AudioCapturerWrapper::Start
    → CreateAudioCapturer (AudioStandard::AudioCapturer)
    → SetupCapturerCallbacks (AudioCapturerCallbackImpl + AudioCapturerReadCallbackImpl)
  → AudioCapturerReadCallbackImpl::OnReadData
    → AudioCapturerWrapper::OnReadData → CacheBuffer 入队
  → 应用 AcquireAudioBuffer / ReleaseAudioBuffer
```

**文件录制流程（FILE_MODE）**：

```
ScreenCaptureServer::StartScreenCaptureFile
  → InitRecorder (IRecorderService)
  → AudioDataSource (IAudioDataSource) 混音数据源
    → innerCapture_ + micCapture_ → MixAudio
    → ReadAt → Recorder 引擎
  → MakeVirtualScreenMirror → 视频帧 → Recorder
  → 文件输出
```

### 使用场景

| 实体 | 适用场景 |
|------|---------|
| ScreenCapBufferConsumerListener | BUFFER_MODE/SURFACE_MODE 视频帧缓冲管理 |
| AudioCapturerWrapper | 内部音频（ALL_PLAYBACK/APP_PLAYBACK）+ 麦克风（MIC）采集 |
| AudioDataSource | FILE_MODE 下混音 + A/V 同步 |
| IRecorderService | FILE_MODE 下文件录制 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 性能约束 | ScreenCapBufferConsumerListener 最大缓冲 3 个 SurfaceBufferEntry，消息队列最大 5 条 |
| 性能约束 | AudioCapturerWrapper 最大音频缓冲 128 个 CacheBuffer |
| 线程安全 | ScreenCapBufferConsumerListener 使用 mutex_ + bufferMutex_ + condition_variable 保护缓冲队列 |
| 线程安全 | AudioCapturerWrapper 使用 mutex_ + bufferMutex_ + shared_mutex(audioCapturerMutex_) 保护采集器状态 |
| 业务规则 | BUFFER_MODE 直接回调原始帧，FILE_MODE 通过 Recorder 引擎编码写文件 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上游依赖 | [[service-layer]] — ScreenCaptureServer 调用采集实现 |
| 外部依赖 | Rosen::ScreenManager — 虚拟屏幕创建/管理 |
| 外部依赖 | AudioStandard::AudioCapturer — 音频采集 |
| 平级关联 | ScreenCapBufferConsumerListener (视频) ↔ AudioCapturerWrapper (音频) — 分别管理视频/音频缓冲 |
| 概念对比 | BUFFER_MODE (原始帧回调) vs FILE_MODE (Recorder 编码写文件) — 两种数据输出路径 |

## 数据模型

### 缓冲队列配置

| 缓冲类型 | 最大队列长度 | 说明 |
|---------|------------|------|
| 视频缓冲 (availBuffers_) | 3 (MAX_BUFFER_SIZE) | SurfaceBufferEntry 队列 |
| 视频消息队列 (messageQueueSCB_) | 5 (MAX_MESSAGE_QUEUE_SIZE) | SCBufferMessage 队列 |
| 音频缓冲 (availBuffers_) | 128 (MAX_AUDIO_BUFFER_SIZE) | CacheBuffer deque |

### A/V 同步算法参数表

| 参数 | 值 | 说明 |
|------|---|------|
| firstAudioFramePts_ | -1（初始） | 首帧音频时间戳 |
| firstVideoFramePts_ | -1（初始） | 首帧视频时间戳（atomic） |
| NEG_AUDIO_INTERVAL_IN_NS | -21333334 ns | 负音频间隔（约 20ms） |
| AUDIO_INTERVAL_IN_NS | 21333334 ns | 音频间隔（约 20ms） |
| MAX_INNER_AUDIO_TIMEOUT_IN_NS | 2000000000 ns | 内部音频最大超时（2s） |
| AUDIO_MIC_TOO_CLOSE_LIMIT_IN_NS | 10000000 ns | 麦克风过近限制（10ms） |
| MAX_MIC_BEFORE_INNER_TIME_IN_NS | 40000000 ns | 麦克风领先内部音频最大时间（40ms） |
| FILL_AUDIO_FRAME_DURATION_IN_NS | 20000000 ns | 填充音频帧时长（20ms） |

### 混音模式表

| 模式 | 值 | 说明 |
|------|---|------|
| MIX_MODE | 0 | 内部音频 + 麦克风混音 |
| MIC_MODE | 1 | 仅麦克风 |
| INNER_MODE | 2 | 仅内部音频 |
| INVALID_MODE | 3 | 无效模式 |

### AVScreenCaptureMixBufferType

| 类型 | 值 | 说明 |
|------|---|------|
| MIX | 0 | 混音数据 |
| MIC | 1 | 麦克风数据 |
| INNER | 2 | 内部音频数据 |
| SILENT | 3 | 静音数据 |
| INVALID | 4 | 无效 |

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| ScreenCapBufferConsumerListener | `services/services/screen_capture/server/screen_cap_buffer_consumer_listener.h/.cpp` | ScreenCapBufferConsumerListener, SurfaceBufferEntry, SCBufferMessage, SurfaceBufferThreadRun |
| AudioCapturerWrapper | `services/services/screen_capture/server/audio_capturer_wrapper.h/.cpp` | AudioCapturerWrapper, AudioCapturerWrapperState, OnReadData |
| AudioCapturerCallbackImpl | `services/services/screen_capture/server/audio_capturer_wrapper.h` L41-L45 | AudioCapturerCallbackImpl::OnInterrupt/OnStateChange |
| AudioCapturerReadCallbackImpl | `services/services/screen_capture/server/audio_capturer_wrapper.h` 第36-第151行 | AudioCapturerReadCallbackImpl::OnReadData |
| AudioDataSource | `services/services/screen_capture/server/audio_data_source.h/.cpp` | AudioDataSource, AVScreenCaptureMixMode, ReadAt, MixAudio |
| CacheBuffer | `services/services/screen_capture/server/cache_buffer.h` | CacheBuffer, WriteTo |
| AudioBuffer | `interfaces/inner_api/native/screen_capture.h` L287-L305 | AudioBuffer |
| 虚拟屏幕实体 | `services/services/screen_capture/server/screen_capture_server.h/.cpp` | MakeVirtualScreenMirror/MakeVirtualScreenExtended/CreateVirtualScreen/DestroyVirtualScreen |
| VideoPermissionState/AVScreenCaptureAvType/AVScreenCaptureDataMode/StopReason | `services/services/screen_capture/server/screen_capture_server_base.h` | 枚举定义 |

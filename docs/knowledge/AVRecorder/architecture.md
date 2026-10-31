# 架构设计及约束

> 录制框架全局性架构设计原则及约束说明

## 架构设计

### 设计原则

| 原则 | 描述 | 理由 |
| -- | -- | -- |
| 分层解耦 | NAPI层、Service层、Engine层、MediaEngine层各层职责清晰，通过接口隔离 | 各层可独立演进、测试和替换，降低耦合度 |
| Pipeline驱动 | 引擎层基于Filter Pipeline构建数据流，各Filter独立可插拔 | 灵活组合音视频采集、编码、水印、封装链路，支持多场景录制 |
| IPC隔离 | 客户端与服务端通过OHOS IPC Proxy/Stub通信，进程隔离 | 保障系统服务稳定性，客户端崩溃不影响媒体服务进程 |
| Source抽象 | 音频源、视频源、元数据源统一抽象为Source，通过sourceId管理 | 统一管理多源录制，简化上层接口 |

### 逻辑架构

录制框架采用四层架构：

```
+----------------------------------------------------------+
|                    应用层 (App)                            |
+----------------------------------------------------------+
|  NAPI层 (frameworks/js/avrecorder)                       |
|  AVRecorderNapi - JS/ArkTS API绑定，状态机管理              |
+----------------------------------------------------------+
|  Service层 (services/services/recorder)                   |
|  RecorderClient ← IPC → RecorderServer                   |
|  (client/)              (server/, ipc/)                   |
+----------------------------------------------------------+
|  Engine层 (services/engine/histreamer/recorder)           |
|  HiRecorderImpl - Pipeline构建与Filter编排                  |
+----------------------------------------------------------+
|  MediaEngine层 (av_codec/services/media_engine)           |
|  Filters: AudioCapture, VideoCapture, Encoder,            |
|  WaterMark, Muxer, MetaData, CodecAdapter                 |
+----------------------------------------------------------+
```

**数据流方向**（以视频录制为例）：

```
Camera → Surface → [WaterMarkFilter] → SurfaceEncoderFilter → MuxerFilter → 文件
Camera → Surface → VideoCaptureFilter → MuxerFilter → 文件
Camera → Surface → MetaDataFilter → MuxerFilter → 文件
AudioCapturer → AudioCaptureFilter → AudioEncoderFilter → MuxerFilter → 文件
```

### 模块职责

| 模块 | 路径 | 类型 | 模块职责 | 其他 |
| -- | -- | -- | -- | -- |
| AVRecorderNapi | frameworks/js/avrecorder | NAPI | JS/ArkTS API层，提供AVRecorder对象，管理状态机和异步任务 | 状态：idle/prepared/started/paused/stopped/released/error |
| RecorderClient | services/services/recorder/client | 客户端 | IPC客户端代理，转发上层调用到服务端 | 通过IStandardRecorderService接口 |
| RecorderServer | services/services/recorder/server | 服务端 | 录制服务端实现，管理配置、状态、回调分发，协调Engine | 运行在media_service进程 |
| IPC层 | services/services/recorder/ipc | IPC | 定义Proxy/Stub，实现跨进程调用 | 包含Service和Listener双向IPC |
| MediaLibraryAdapter | services/services/recorder/server | 适配器 | 对接MediaLibrary服务，创建媒体资产 | 支持APP_CREATE和AUTO_CREATE模式 |
| HiRecorderImpl | services/engine/histreamer/recorder | 引擎 | IRecorderEngine实现，构建Pipeline、管理Filter生命周期 | 基于Histreamer Pipeline框架 |
| AudioCaptureFilter | av_codec/services/media_engine/filters | Filter | 音频采集，封装AudioCapturer | 支持AUDIO_SOURCE_MIC等源 |
| AudioDataSourceFilter | av_codec/services/media_engine/filters | Filter | 外部音频数据源输入 | 支持IAudioDataSource接口 |
| AudioEncoderFilter | av_codec/services/media_engine/filters | Filter | 音频编码，对接Codec | 支持AAC等格式 |
| VideoCaptureFilter | av_codec/services/media_engine/filters | Filter | 视频Surface输入采集 | 从Camera Surface获取视频帧 |
| SurfaceEncoderFilter | av_codec/services/media_engine/filters | Filter | 视频编码，支持硬件/软编码 | 通过SurfaceEncoderAdapter对接Codec |
| WaterMarkFilter | av_codec/services/media_engine/filters | Filter | 水印叠加，支持软硬件水印融合 | 最多5个水印，基于OpenGL渲染 |
| MuxerFilter | av_codec/services/media_engine/filters | Filter | 封装器，将编码后音视频数据写入文件 | 支持MP4/M4A/AMR/MP3/WAV/AAC |
| MetaDataFilter | av_codec/services/media_engine/filters | Filter | 元数据轨道处理 | 支持timed metadata写入 |
| CodecCapabilityAdapter | av_codec/services/media_engine/filters | Filter | 编解码能力查询适配器 | 查询硬件编码器能力 |

### 技术选型

| 类别 | 技术选型 | 说明 |
| -- | ---- | -- |
| 语言 | C++17（核心） / ArkTS（NAPI绑定） | 系统服务层使用C++，JS API层使用NAPI |
| 构建系统 | GN + Ninja | OpenHarmony标准构建 |
| 进程间通信 | OHOS IPC（IRemoteStub/Proxy） | 客户端与服务端跨进程通信 |
| 数据流引擎 | Histreamer Pipeline + Filter | Filter可插拔的Pipeline架构 |
| 音频采集 | AudioCapturer（Audio标准库） | 支持MIC/VOICE_COMMUNICATION等源 |
| 视频编码 | Codec（硬件/软件编码器） | 通过SurfaceEncoderAdapter对接 |
| 水印渲染 | OpenGL ES | WaterMarkFilter使用GPU渲染水印 |
| 封装 | MediaMuxer | 支持MP4等容器格式 |
| 日志 | HiLog | 分模块标签，遵循HiLog规范 |

### 基础设施

| 基础设施 | 功能说明 | 关键接口描述 |
| -- | ---- | ---- |
| TaskQueue | 异步任务队列，NAPI和Server层均使用 | TaskQueue.PushTask / TaskHandler |
| IPC框架 | 客户端-服务端通信 | IStandardRecorderService / RecorderListenerStub |
| Pipeline框架 | Filter编排与数据流管理 | Pipeline::AddFilter / Pipeline::LinkFilters / Filter::SendEos |
| AVBufferQueue | Filter间数据传递 | AVBufferQueueProducer / AVBufferQueueConsumer |
| Callback机制 | 错误/信息/状态变更回调 | RecorderCallback::OnError / OnInfo |
| WatchDog | 录制超时保护（Server层） | WatchDog监控录制进程 |

### 非功能设计

#### 可测试性设计

| 可测试性场景 | 方案设计 |
| ---- | ---- |
| NAPI层接口测试 | 通过NAPI单元测试框架验证JS API |
| Service层单元测试 | Mock IPC层和Engine层，测试Server逻辑 |
| Engine层Pipeline测试 | Mock Filter，验证Pipeline构建和状态流转 |
| Filter级单元测试 | 各Filter独立测试，Mock上下游Buffer |

#### 可靠性设计

| 可靠性场景 | 方案设计 |
| ---- | ---- |
| 客户端崩溃 | IPC连接断开，Server自动释放录制资源 |
| 编码器异常 | Engine上报错误，Server回调应用，状态转为ERROR |
| 文件写入失败 | MuxerFilter上报错误，应用可重试或释放 |
| 系统关机 | SaveDocumentSyncCallback监听关机事件，停止录制 |

#### 性能设计

| 性能场景 | 方案设计 |
| ---- | ---- |
| 视频编码延迟 | 使用硬件编码器，减少CPU开销 |
| 音视频同步 | MuxerFilter内维护音视频PTS同步，阈值200ms |
| 水印渲染性能 | 使用OpenGL GPU渲染，避免CPU软件叠加 |

#### 内存设计

| 内存场景 | 方案设计 |
| ---- | ---- |
| AVBuffer生命周期 | Buffer由AVBufferQueue管理，Filter间传递shared_ptr |
| Pipeline资源释放 | Stop/Reset时清空Pipeline和所有Filter |
| Surface Buffer | 通过BufferQueue机制管理，避免泄漏 |

#### 安全与隐私设计

| 安全与隐私场景 | 设计方案 |
| ---- | ---- |
| 麦克风权限 | 音频采集需ohos.permission.MICROPHONE |
| 摄像头权限 | 视频录制需ohos.permission.CAMERA |
| 文件访问 | 通过fd写入，不直接操作文件路径 |

## 架构约束

- **IPC是模块边界**
  - **what**：客户端与服务端必须通过IPC Proxy/Stub通信
  - **why**：进程隔离保障系统服务稳定性
  - **how**：RecorderClient通过IStandardRecorderService Proxy调用，回调通过RecorderListenerStub上报

- **Pipeline是引擎核心**
  - **what**：所有录制数据流必须通过Filter Pipeline编排
  - **why**：保证数据流路径可追踪、可插拔、可扩展
  - **how**：HiRecorderImpl通过Pipeline::AddFilter/LinkFilters构建链路，禁止绕过Pipeline直接操作Filter

- **状态机严格管控**
  - **what**：操作必须在合法状态下调用，否则返回MSERR_INVALID_OPERATION
  - **why**：防止非法操作导致录制异常
  - **how**：NAPI层stateCtrlList定义每个状态允许的操作，Server层RecStatus校验

- **Source类型不可混用**
  - **what**：SetVideoSource/SetAudioSource/SetMetaSource必须在SetOutputFormat之前调用
  - **why**：Source决定Pipeline拓扑，后续不可更改
  - **how**：Engine层通过curState_校验，INIT状态才接受Source设置

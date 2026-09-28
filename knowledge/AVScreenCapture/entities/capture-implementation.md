# 采集实现实体

> 虚拟屏幕、音频采集、缓冲管理、A/V 同步等屏幕录制采集实现层（无独立引擎层，采集逻辑内置于 ScreenCaptureServer）

## 实体概念

| 实体名称 | 实体定义 | 类型/分类 |
|---------|---------|----------|
| 虚拟屏幕实体 | ScreenCaptureServer 内置的虚拟屏幕管理方法集（镜像/扩展/创建/销毁/切换/初始化选项） | 采集实现 |
| Rosen::ScreenManager | 外部依赖，Rosen 图形框架屏幕管理 | 外部依赖 |
| Surface / SurfaceBuffer | 视频帧数据载体（Consumer/Producer Surface） | 缓冲载体 |
| ScreenCapBufferConsumerListener | 视频缓冲消费者监听，独立线程获取 SurfaceBuffer 回调应用 | 缓冲监听 |
| AudioCapturerWrapper | 音频采集封装，封装 AudioStandard::AudioCapturer，独立状态机 | 音频采集封装 |
| AudioCapturerCallbackImpl / ReadCallbackImpl | 音频中断/状态变化/数据读取回调 | 音频回调 |
| AudioDataSource | 混音 + 同步，实现 IAudioDataSource | 混音/同步 |
| CacheBuffer | 音频缓冲区封装 | 音频缓冲 |
| AudioBuffer | 音频缓冲区结构 | 缓冲结构 |
| IRecorderService | 文件录制复用的 Recorder 引擎接口 | 外部引擎接口 |
| VideoPermissionState | 视频权限状态枚举（START_VIDEO/STOP_VIDEO） | 枚举 |
| AVScreenCaptureAvType | 音视频类型枚举 | 枚举 |
| AVScreenCaptureDataMode | 数据模式枚举（BUFFER_MODE/SURFACE_MODE/FILE_MODE） | 枚举 |
| StopReason | 停止原因枚举 | 枚举 |

## 交互流程

**视频采集流程（BUFFER_MODE / SURFACE_MODE）**：
Server 创建虚拟屏幕(镜像/扩展) → BufferConsumerListener 启动缓冲线程 → OnBufferAvailable → 回调应用 → 应用 Acquire/Release VideoBuffer

**音频采集流程（BUFFER_MODE）**：
Server 启动音频采集 → Wrapper 封装 AudioCapturer → 数据读取回调 → CacheBuffer 入队 → 应用 Acquire/Release AudioBuffer

**文件录制流程（FILE_MODE）**：
Server 初始化 Recorder → AudioDataSource(混音数据源) 提供混音音频 → 虚拟屏幕 Surface 提供视频 → Recorder 引擎编码封装 → 文件输出

## 使用场景

| 实体 | 适用场景 |
|------|---------|
| ScreenCapBufferConsumerListener | BUFFER_MODE/SURFACE_MODE 视频帧缓冲管理 |
| AudioCapturerWrapper | 内部音频(ALL_PLAYBACK/APP_PLAYBACK) + 麦克风(MIC)采集 |
| AudioDataSource | FILE_MODE 下混音 + A/V 同步 |
| IRecorderService | FILE_MODE 下文件录制 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 性能约束 | 视频缓冲为有界队列，防止积压；消息队列有上限 |
| 性能约束 | 音频缓冲为有界队列，满时丢弃旧帧 |
| 线程安全 | 缓冲监听使用互斥锁+条件变量保护队列 |
| 线程安全 | 音频采集封装使用互斥锁+读写锁保护采集器状态 |
| 业务规则 | BUFFER_MODE 直接回调原始帧，FILE_MODE 通过 Recorder 编码写文件 |

### 混音模式

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

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上游依赖 | [service-layer](service-layer.md) — ScreenCaptureServer 调用采集实现 |
| 外部依赖 | Rosen::ScreenManager — 虚拟屏幕创建/管理 |
| 外部依赖 | AudioStandard::AudioCapturer — 音频采集 |
| 平级关联 | BufferConsumerListener(视频) ↔ AudioCapturerWrapper(音频) — 分别管理视频/音频缓冲 |
| 概念对比 | BUFFER_MODE(原始帧回调) vs FILE_MODE(Recorder 编码写文件) — 两种数据输出路径 |

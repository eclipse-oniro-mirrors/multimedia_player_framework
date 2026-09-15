# 业务背景

## 应用定位

### 核心职责
本框架负责 **音视频录制** ，为 **上层应用（相机、录屏、通话录音等）** 提供 **音视频采集、编码、封装和文件输出** 能力，是 **HarmonyOS多媒体** 在媒体录制领域的关键基础组件。

### 核心价值
- 为应用提供统一的JS/ArkTS录制API（AVRecorder），屏蔽底层Pipeline复杂性
- 支持纯音频、纯视频、音视频同步录制多种场景
- 支持水印叠加（软/硬件融合），满足版权保护和合规需求
- 支持元数据轨道（timed metadata），满足录屏场景附加信息需求
- 提供录制配置查询（编码能力、Profile），辅助应用适配设备

### 职责边界（本框架不负责）
- 不负责Camera预览和拍照（由Camera框架负责）
- 不负责音频焦点管理和音频策略（由Audio框架负责）
- 不负责文件管理和媒体库资产维护（由MediaLibrary负责，框架仅通过fd或adapter对接）
- 不负责视频解码和播放（由Player框架负责）

## 系统上下文

### 外部系统
- **Camera服务**：提供视频帧数据，通过Surface传递YUV/RGBA/ES数据
- **Audio服务（AudioCapturer）**：提供音频PCM数据采集
- **Codec服务（AVCodec）**：提供音视频硬件/软件编码能力
- **MediaLibrary服务**：管理录制输出文件的媒体资产信息
- **DisplayManager**：录屏场景下提供屏幕画面数据
- **PowerManager**：系统关机时通知录制框架停止录制

### 交互上下文

**交互说明**：
| 交互路径 | 方向 | 交互内容 | 交互意图 |
| ---- | -- | ---- | ---- |
| 应用 ↔ AVRecorderNapi | ↔ | JS API调用和回调 | 应用发起录制操作，接收状态和错误回调 |
| RecorderClient → RecorderServer | → | IPC调用 | 跨进程转发录制操作 |
| RecorderServer → HiRecorderImpl | → | Engine接口调用 | 驱动录制引擎执行 |
| HiRecorderImpl → AudioCaptureFilter | → | 音频采集控制 | 启动/停止音频采集 |
| HiRecorderImpl → VideoCaptureFilter | → | Surface管理 | 获取视频输入Surface |
| HiRecorderImpl → SurfaceEncoderFilter | → | 编码控制 | 配置和启动视频编码 |
| HiRecorderImpl → WaterMarkFilter | → | 水印配置 | 设置水印图片和位置 |
| HiRecorderImpl → MuxerFilter | → | 封装控制 | 配置输出格式和文件fd |
| MuxerFilter → MediaMuxer | → | 封装写入 | 编码后数据封装写入文件 |
| MediaLibraryAdapter → MediaLibrary | → | 资产创建 | AUTO_CREATE模式下自动创建媒体资产 |
| RecorderServer → PowerManager | → | 关机监听 | 注册关机回调，紧急停止录制 |

## 核心业务场景

### 1. 视频录制（相机场景）
Camera应用通过AVRecorder录制视频：配置音视频源 → Prepare → 获取Surface → Camera输出到Surface → Start录制 → Stop → Release

### 2. 音频录制（录音场景）
录音应用通过AVRecorder录制音频：配置音频源 → Prepare → Start录制 → Stop → Release

### 3. 屏幕录制（录屏场景）
系统应用通过AVRecorder录屏：配置视频源（SURFACE_ES）+ 元数据源 → Prepare → 获取Surface和MetaSurface → 屏幕数据输入 → Start录制 → 带水印录制 → Stop

### 4. 音视频+水印录制
应用在录制同时叠加水印：配置音视频源 → Prepare → IsWatermarkSupported → SetWatermark/AddWatermark → Start → 带水印视频输出

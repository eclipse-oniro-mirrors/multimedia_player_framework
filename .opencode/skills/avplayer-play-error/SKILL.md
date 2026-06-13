# AVPlayer 播放失败分析

> **版本**: v1.2
> **更新日期**: 2026-05-28
> **适用场景**: AVPlayer 播放失败问题原因和解决方案分析
> **文档类型**: Skill定义文件

本文档定义了 AVPlayer 播放失败回调错误码的分析规则和排查方法。agent 应按此规则分析 OnErrorCb 回调和错误码，定位播放失败的根本原因。

**v1.2更新内容**：
- 新增"播放流程与异常定位"章节
- 详细说明AVPlayer播放流程：Source → Demuxer → Decoder → Sink
- 为每个播放环节（Source、Demuxer、AudioDecoder、VideoDecoder、Sink）添加异常日志特征
- 提供各环节的典型异常案例和错误码映射
- 增加异常定位方法，帮助快速定位具体异常环节

**v1.1更新内容**：
- 新增AVPlayer使用检测功能，通过PrintCaller关键字判断应用是否使用AVPlayer
- 优化分析流程，在错误分析前先确认播放器类型
- 提供明确的分析路径选择（AVPlayer vs 直接解码器）

---

## 目录

- [适用场景](#适用场景)
- [使用说明](#使用说明)
- [AVPlayer使用检测](#avplayer使用检测)
- [播放流程与异常定位](#播放流程与异常定位)
- [错误回调识别](#错误回调识别)
- [错误码对照表](#错误码对照表)
- [各阶段错误码详解](#各阶段错误码详解)
- [错误定位流程](#错误定位流程)
- [常见错误码排查](#常见错误码排查)
- [典型问题案例](#典型问题案例)
- [错误码快速索引](#错误码快速索引)

---

## 适用场景

- AVPlayer 播放失败问题分析
- OnErrorCb 回调错误码定位
- 播放器状态异常问题排查
- 错误码根因分析和解决建议
- 检测应用是否使用AVPlayer播放器
- 区分AVPlayer和直接调用解码器的不同分析路径

---

## 使用说明

### 分析流程
0. 检测应用是否使用AVPlayer（通过PrintCaller关键字）
1. 识别日志中的错误回调（OnErrorCb）
2. 提取错误码和错误信息
3. 对照错误码表确定错误类型
4. 结合上下文日志定位失败阶段
5. 分析根本原因并提供解决建议

### 判定规则
- **播放失败**: 匹配到 `OnErrorCb` 或 `PLAYER_STATE_ERROR`
- **错误码提取**: 从日志中提取 `errorCode` 字段
- **阶段定位**: 根据错误码和前后日志确定失败阶段
- **根因分析**: 结合媒体信息、环境信息分析具体原因

### 注意事项
- 错误码是 7 位数字（如 5400100）
- 关注错误日志前后的上下文（前后 5-10 行）
- 区分播放类型（直播/点播）和媒体类型（纯音频/纯视频/音视频）
- 某些错误码可能有多个可能原因，需要结合具体情况分析

---

## AVPlayer使用检测

### 检测目的

在进行播放失败问题定位时，首先需要确认应用是否使用了AVPlayer播放器。不同的播放方式（AVPlayer vs 直接调用解码器）需要采用不同的分析路径和排查方法。

### 检测方法

通过分析解码器服务日志中的 `PrintCaller` 关键字来判断应用是否使用了AVPlayer：

#### 判断依据

| 调用链模式 | 是否使用AVPlayer | 说明 |
|-----------|----------------|------|
| `-> player -> avcodec` | 是 | 调用链经过player中间层，使用AVPlayer |
| `-> avcodec` | 否 | 直接调用avcodec，未使用AVPlayer |

#### 检测步骤

1. 搜索解码器服务日志中的 `PrintCaller` 关键字
   ```
   搜索模式: PrintCaller.*av_codec_service/HCODEC
   ```

2. 检查调用链中是否包含 `player` 关键字
   ```
   包含 "player" → 使用AVPlayer
   不包含 "player" → 未使用AVPlayer
   ```

3. 根据检测结果选择相应的分析路径

### 日志示例

#### 使用AVPlayer的日志

```
12-02 11:02:25.215  1663 37705 I C02B32/av_codec_service/HCODEC: [985_e Uninit PrintCaller] [pid 13622][com.xx.camera] -> player -> avcodec
```

**特征分析**：
- 调用链: `[pid 13622][com.xx.camera] -> player -> avcodec`
- 包含 `player` 中间层
- **结论**: 使用了AVPlayer

#### 未使用AVPlayer的日志

```
11-10 17:27:55.423  1614 22785 I C02B32/av_codec_service/HCODEC: [521_e Uninit PrintCaller] [pid 22751][/system/bin/uitest] -> avcodec
```

**特征分析**：
- 调用链: `[pid 22751][/system/bin/uitest] -> avcodec`
- 直接调用avcodec，无player中间层
- **结论**: 未使用AVPlayer

### 分析路径选择

#### 使用AVPlayer的分析路径

1. 按照本文档的AVPlayer错误码分析流程进行
2. 检查JS API层、数据读取层、解封装层、解码层、送显层
3. 参考avplayer_patterns.md中的各阶段匹配规则
4. 使用AVPlayer专用的错误码和状态机

#### 未使用AVPlayer的分析路径

1. 直接从解码器层面分析问题
2. 检查avcodec相关的错误日志
3. 分析解码器配置、输入输出参数
4. 检查码流格式和解码器能力匹配

### 注意事项

- `PrintCaller` 日志可能在解码器初始化（Init）或反初始化（Uninit）时打印
- 某些场景下可能需要检查多个 `PrintCaller` 日志来确认
- 对于使用AVPlayer的场景，优先使用本错误码文档进行分析

---

## 播放流程与异常定位

### AVPlayer播放流程概述

AVPlayer的播放流程主要包含以下环节：

```
Source（数据源） → Demuxer（解封装） → Decoder（解码器） → Sink（输出）
                                                    ↓
                                              AudioDecoder（音频解码）
                                              VideoDecoder（视频解码）
```

各环节职责：

| 环节 | 职责 | 主要组件 |
|------|------|----------|
| Source | 数据读取，支持网络/本地/Asset等 | DataSource, NetworkClient |
| Demuxer | 解封装，分离音视频流 | Demuxer, AVFormatContext |
| AudioDecoder | 音频解码 | AudioDecoder, AVCodecContext |
| VideoDecoder | 视频解码 | VideoDecoder, AVCodecContext |
| Sink | 音频输出和视频送显 | AudioSink, VideoSink, Surface |

### Source环节异常

Source环节负责从各种数据源（网络、本地文件等）读取媒体数据。

#### 异常日志特征

```
# 网络异常
05-08 22:01:19.000	1778 38952 E C02B3A/media service/MediaDemuxer:	(HandleEvent ()	3600): HandleEvent CLIENT/SERVER ERROR

# 文件资源异常
05-07 18:58:37.399	1663	6460 I C02B22/media service/FileFdSourcePlugin:	(ParseUriInfo(), 421): Fd: 14, offset: O, size: 0

# 文件资源异常，导致解封装嗅探失败
05-16 05:46:35.883	1499	23501 E C02B22/media service/DemuxerPluginManager: (LoadDemuxerPlugin(), 313): SnifferMediaType is failed.
05-16 05:46:35.883	1499	23501 E C02B22/media service/DemuxerPluginManager: (LoadCurrentAllPlugin(), 337): LoadDemuxerPlugin video plugin failed.
05-16 05:46:35.883	1499	23501	E C02B3A/media service/MediaDemuxer: (InnerPrepare(), 871): Parse meta failed, ret: -7
```

#### 典型案例

**案例1：网络连接超时**
```
05-08 22:01:19.000	1778 38952 E C02B3A/media service/MediaDemuxer:	(HandleEvent ()	3600): HandleEvent CLIENT/SERVER ERROR
```
**分析**：Source返回数据异常报错，CLIENT/SERVER ERROR表示网络异常

**案例2：文件资源异常**
```
05-07 18:58:37.399	1663	6460 I C02B22/media service/FileFdSourcePlugin:	(ParseUriInfo(), 421): Fd: 14, offset: O, size: 0
```
**分析**：Source环节本地文件fd异常，size: 0表示文件内容为空

### Demuxer环节异常

Demuxer环节负责解封装，将媒体容器格式（如MP4、AVI、MKV等）中的音视频流分离出来。

#### 异常日志特征

```
# 解封装失败
.*Demuxer.*open.*fail
.*avformat.*open.*input.*fail
.*Invalid.*format

# 流信息获取失败
.*find.*stream.*info.*fail
.*could.*not.*find.*codec.*parameters

# 码流格式不支持
.*Unsupported.*codec
.*codec.*not.*found
.*unknown.*format

# 解封装过程异常
.*demux.*error
.*read.*packet.*fail
.*invalid.*data
```

#### 典型案例

**案例1：不支持的媒体格式**
```
09-01 15:26:34.424	716	4028 W CO2b3a/FfmpegFormatHelper: (ParseBaseTrackInfo(), 722): Pause mime type failed: wmav2
09-01 15:26:34.424	716	4028 W CO2b3a/FfmpegFormatHelper: (ParseBaseTrackInfo(), 722): Parse mime type failed: wmvl
09-01 15:26:34.425	716	4029 E C02b2b/PlayerListenerProxy: #112 player callback onBrzor, errorCode: 331350544, errorMsg: unsupport interface, unsupport container format type
```
**分析**：Demuxer环节检测到不支持的媒体格式，错误码5400106表示UNSUPPORTED_FORMAT

**案例2：码流损坏**
```
05-09 16:18:39.892 64008 64008 E A0FF00/net.video.player/[Samples_VideoPlay]: AVPlayManager, error happened,and error message is :IO Error: DEM_PARSE_ERR-video/hevc-unkown error, media data source error unknow
```
**分析**：Demuxer环节读取到损坏的数据

### AudioDecoder环节异常

AudioDecoder环节负责音频解码，将压缩的音频数据（如AAC、MP3等）解码为PCM数据。

#### 异常日志特征

```
# 音频解码器初始化失败
AudioDecoder error: 5400102 Invalid Parameter: audioDecoder start failed

# 音频解码失败
09-15 22:20:37.817 1593 5795E C02B31/media service/AvCodec-FfmpegBaseDecoder: {SendBuffer(:136} error msg:Invalid data found when processing input
09-15 22:20:37.817 1593 5795E C02B3A/media service/FfmpegDemuxerPlugin: (FfmpegLogPrint(), 407): [FFLogE] channel element 0.0 duplicate

# 不支持的音频格式
AVPLayerController: avPLayer updateOnError error: 5400106 Unsupported Format: AUD_DEC_ERR-audio/mp4a-Latm-unsupport interface, unsupport audio decoder type
AVPLayerController: Unsupported Format: 5400106 Unsupported Format: AUD_DEC_ERR-audio/mp4a-Latm-unsupport interface, unsupport audio decoder type
```

#### 典型案例

**案例1：不支持的音频编码格式**
```
AVPLayerController: avPLayer updateOnError error: 5400106 Unsupported Format: AUD_DEC_ERR-audio/mp4a-Latm-unsupport interface, unsupport audio decoder type
AVPLayerController: Unsupported Format: 5400106 Unsupported Format: AUD_DEC_ERR-audio/mp4a-Latm-unsupport interface, unsupport audio decoder type
```
**分析**：AudioDecoder环节检测到不支持的音频编码格式，错误码5400106表示AUDIO_CODEC_NOT_SUPPORTED

**案例2：音频解码失败**
```
09-15 22:20:37.817 1593 5795E C02B31/media service/AvCodec-FfmpegBaseDecoder: {SendBuffer(:136} error msg:Invalid data found when processing input
09-15 22:20:37.817 1593 5795E C02B3A/media service/FfmpegDemuxerPlugin: (FfmpegLogPrint(), 407): [FFLogE] channel element 0.0 duplicate
```
**分析**：AudioDecoder环节解码音频帧失败

**案例3：音频解码器初始化失败**
```
AudioDecoder error: 5400102 Invalid Parameter: audioDecoder start failed
```
**分析**：AudioDecoder初始化环节异常

### VideoDecoder环节异常

VideoDecoder环节负责视频解码，将压缩的视频数据（如H.264、H.265等）解码为YUV数据。

#### 异常日志特征

```
# 视频解码器初始化失败
video decoder start failed

# 视频解码失败
04-07 20:11:26.956	1481 61740 E CO2B90/av codec service/OMXComponentDecoder: VIDEO:[FillThisMetaDataBuffer]:[455] create vcodecbuffer failed
04-07 20:11:26.956	1491 60891 W CO2B30/media service/CodecClient: [690][h.vdec]{OnError) unknown error
04-07 20:11:26.956	1491 60891 E CO2B22/media service/DecoderSurfaceFilter: (OnError(), 292): AVCodec error happened. ErrorType: errorCode: 63570432

# 硬解不支持切软解，软解视频分辨率超出支持范围
11-28 10:25:23.062  1644  1917 E C02B22/media_service/DecoderSurfaceFilter: (OnError(), 287): AVCodec error happened. ErrorType: 0, errorCode: 63570486
11-28 10:25:24.171  1608  1766 E C02B30/av_codec_service/CodecParamChecker: {ResolutionChecker} Param invalid, resolution: 3840*2160, range: [2*2]-[1920*1920]
11-28 10:25:24.171  1608  1766 E C02B30/av_codec_service/CodecParamChecker: {CheckConfigureValid} Param check failed
11-28 10:25:24.171  1608  1766 E C02B30/av_codec_service/CodecServer: [12][s.vdec]{Configure} Params in format is not valid

# 不支持的视频格式
04-01 18:25:34.764 1614 63570 W C02B30/media service/CodecClient: [4059][h.vdea](OnError) unsupported codec specification
04-01 18:25:34.764 1614 63570 E C02B22/media_service/DecoderSurfaceFilter: (OnErrorO,288):AVCodec error happened. ErrorType: O, errorCode: 63570486
```

#### 典型案例

**案例1：不支持的视频编码格式**
```
04-01 18:25:34.764 1614 63570 W C02B30/media service/CodecClient: [4059][h.vdea](OnError) unsupported codec specification
04-01 18:25:34.764 1614 63570 E C02B22/media_service/DecoderSurfaceFilter: (OnErrorO,288):AVCodec error happened. ErrorType: O, errorCode: 63570486
```
**分析**：VideoDecoder环节检测到不支持的视频编码格式

**案例2：视频解码失败**
```
04-07 20:11:26.956	1481 61740 E CO2B90/av codec service/OMXComponentDecoder: VIDEO:[FillThisMetaDataBuffer]:[455] create vcodecbuffer failed
04-07 20:11:26.956	1491 60891 W CO2B30/media service/CodecClient: [690][h.vdec]{OnError) unknown error
04-07 20:11:26.956	1491 60891 E CO2B22/media service/DecoderSurfaceFilter: (OnError(), 292): AVCodec error happened. ErrorType:	errorCode: 63570432
```
**分析**：VideoDecoder环节解码视频帧失败

**案例3：硬解不支持切软解，软解视频分辨率超出支持范围**
```
11-28 10:25:23.062  1644  1917 E C02B22/media_service/DecoderSurfaceFilter: (OnError(), 287): AVCodec error happened. ErrorType: 0, errorCode: 63570486
11-28 10:25:24.171  1608  1766 E C02B30/av_codec_service/CodecParamChecker: {ResolutionChecker} Param invalid, resolution: 3840*2160, range: [2*2]-[1920*1920]
11-28 10:25:24.171  1608  1766 E C02B30/av_codec_service/CodecParamChecker: {CheckConfigureValid} Param check failed
11-28 10:25:24.171  1608  1766 E C02B30/av_codec_service/CodecServer: [12][s.vdec]{Configure} Params in format is not valid
```
**分析**：VideoDecoder环节检测到视频分辨率超出支持范围

**案例4：解码器初始化失败**
```
video decoder start failed
```
**分析**：视频解码器初始化失败

### Sink环节异常

Sink环节负责将解码后的数据输出，包括音频输出到扬声器、视频输出到显示器。

#### 异常日志特征

```
# AudioRenderer启动失败
AudioRenderer::Start failed
```

#### 典型案例

**案例1：音频输出设备异常**
```
02-27 14:22:58.059 1512 2366 E C02B22/media_service/HiStreamer: (Start(), 432): AudioRenderer::Start failed
```
**分析**：音频框架AudioRenderer启动失败


### 异常定位方法

#### 步骤1：识别异常环节

根据错误日志中的关键字，定位到具体异常环节：

| 关键字 | 异常环节 |
|--------|----------|
| FileFdSourcePlugin, HttpSourcePlugin, DataStreamSourcePlugin, Histreamer| Source |
| DemuxerFilter, MediaDemuxer, FfmpegDemuxerPlugin | Demuxer |
| AudioDecoder, audio decode | AudioDecoder |
| VideoDecoder, video decode | VideoDecoder |
| AudioSink, audio render, AudioRender | AudioSink |
| VideoSink, DecoderSurfaceFilter| VideoSink |

#### 步骤2：结合错误码确认

根据错误码范围确认异常类型：

| 错误码范围 | 异常类型 |
|------------|----------|
| 5411xxx | Source（IO相关） |
| 540010x | 通用错误（内存、权限等） |
| 540020x | 音频相关 |
| 540030x | 视频相关 |

#### 步骤3：查看上下文日志

查看异常日志前后5-10行，了解异常发生时的状态：
- 播放器状态
- 媒体信息（分辨率、码率、编码格式等）
- 环境信息（网络、内存、设备状态等）

---

## 错误回调识别

### 关键日志模式

```
OnErrorCb
PLAYER_STATE_ERROR
SignError
Callback State change.*PLAYER_STATE_ERROR
```

### 错误码提取模式

```
errorCode:\s*(\d{7})
OnErrorCb:errorCode\s+(\d{7})
```

### 错误信息提取模式

```
errorMsg:\s*(.+)
error.*message:\s*(.+)
```

### 示例日志

```
# 标准错误回调
05-13 18:03:48.280   609   628 E PLAYER: OnErrorCb:errorCode 5400106, errorMsg Unsupported Format

# 状态错误
05-13 18:03:48.280   609   628 E PLAYER: Callback State change, currentState is PLAYER_STATE_ERROR

# 当前调用不符合状态机要求
05-13 18:03:48.280   609   628 E PLAYER: SignError, current state is not prepared/paused/completed, unsupport play operation

# 给应用上报错误信息
05-13 18:03:48.280   609   628 E bootanimation: errorMsg:AUD_OUTPUT_ERR-null-unsupport interface, audio render failed
```

---

## 错误码对照表

### 官方错误码定义（enum MediaServiceExtErrCodeAPI9）

```cpp
enum MediaServiceExtErrCodeAPI9 : int32_t {
    MSERR_EXT_API9_OK = 0,                          // 成功
    MSERR_EXT_API9_NO_PERMISSION = 201,             // 权限拒绝 (AccessToken)
    MSERR_EXT_API9_PERMISSION_DENIED = 202,         // 权限拒绝 (system API)
    MSERR_EXT_API9_INVALID_PARAMETER = 401,         // 参数错误
    MSERR_EXT_API9_UNSUPPORT_CAPABILITY = 801,      // 不支持的能力

    // 54xxxxx 系列错误码
    MSERR_EXT_API9_NO_MEMORY = 5400101,             // 内存不足
    MSERR_EXT_API9_OPERATE_NOT_PERMIT = 5400102,    // 操作不允许
    MSERR_EXT_API9_IO = 5400103,                    // IO 错误
    MSERR_EXT_API9_TIMEOUT = 5400104,               // 操作超时
    MSERR_EXT_API9_SERVICE_DIED = 5400105,          // 媒体服务死亡
    MSERR_EXT_API9_UNSUPPORT_FORMAT = 5400106,      // 不支持的格式
    MSERR_EXT_API9_AUDIO_INTERRUPTED = 5400107,     // 音频中断
    MSERR_EXT_API20_PARAM_ERROR_OUT_OF_RANGE = 5400108,  // 参数超出范围
    MSERR_EXT_API20_SESSION_NOT_EXIST = 5400109,         // 会话不存在
    MSERR_EXT_API20_HARDWARE_FAILED = 5400201,           // 硬件失败

    // 541xxxx 系列错误码
    MSERR_EXT_API16_SEEK_CONTINUOUS_UNSUPPORTED = 5410002,      // 不支持连续 seek
    MSERR_EXT_API16_SUPER_RESOLUTION_UNSUPPORTED = 5410003,     // 超分不支持
    MSERR_EXT_API16_SUPER_RESOLUTION_NOT_ENABLED = 5410004,     // 超分未启用

    // IO 相关错误码（5411xxx）
    MSERR_EXT_API14_IO_CANNOT_FIND_HOST = 5411001,              // 找不到主机
    MSERR_EXT_API14_IO_CONNECTION_TIMEOUT = 5411002,            // 连接超时
    MSERR_EXT_API14_IO_NETWORK_ABNORMAL = 5411003,              // 网络异常
    MSERR_EXT_API14_IO_NETWORK_UNAVAILABLE = 5411004,           // 网络不可用
    MSERR_EXT_API14_IO_NO_PERMISSION = 5411005,                 // 无权限
    MSERR_EXT_API14_IO_NETWORK_ACCESS_DENIED = 5411006,         // 访问被拒绝
    MSERR_EXT_API14_IO_RESOURE_NOT_FOUND = 5411007,             // 资源未找到
    MSERR_EXT_API14_IO_SSL_CLIENT_CERT_NEEDED = 5411008,        // 需要 SSL 客户端证书
    MSERR_EXT_API14_IO_SSL_CONNECT_FAIL = 5411009,              // SSL 连接失败
    MSERR_EXT_API14_IO_SSL_SERVER_CERT_UNTRUSTED = 5411010,     // 服务器证书不受信任
    MSERR_EXT_API14_IO_UNSUPPORTTED_REQUEST = 5411011,          // 不支持的请求
    MSERR_EXT_API20_IO_CLEARTEXT_NOT_PERMITTED = 5411012,       // 不允许明文传输
};
```

### 错误码分类对照表

#### 权限和参数错误（2xx, 4xx, 8xx）

| 错误码 | 错误名称 | 所属阶段 | 常见原因 | 解决方案 |
|--------|---------|---------|---------|---------|
| 201 | NO_PERMISSION | 权限管理 | AccessToken 权限拒绝 | 检查权限配置 |
| 202 | PERMISSION_DENIED | 权限管理 | 系统 API 权限拒绝 | 检查系统权限 |
| 401 | INVALID_PARAMETER | JS API | 参数错误 | 检查传入参数 |
| 801 | UNSUPPORT_CAPABILITY | JS API | 不支持的能力 | 检查 API 版本和设备能力 |

#### 通用和系统错误（5400101-5400109）

| 错误码 | 错误名称 | 所属阶段 | 常见原因 | 解决方案 |
|--------|---------|---------|---------|---------|
| 5400101 | NO_MEMORY | 通用 | 内存不足 | 释放内存或降低画质 |
| 5400102 | OPERATE_NOT_PERMIT | JS API | 状态不允许当前操作 | 检查播放器状态机 |
| 5400103 | IO | 数据读取 | IO 错误 | 检查文件或网络连接 |
| 5400104 | TIMEOUT | 通用 | 操作超时 | 检查网络或性能 |
| 5400105 | SERVICE_DIED | 系统 | 媒体服务死亡 | 重启播放器或设备 |
| 5400106 | UNSUPPORT_FORMAT | 数据读取/解封装 | 不支持的媒体格式 | 转码文件或检查格式 |
| 5400107 | AUDIO_INTERRUPTED | 音频 | 音频中断 | 检查音频焦点和策略 |
| 5400108 | PARAM_ERROR_OUT_OF_RANGE | JS API | 参数超出范围 | 检查参数值范围 |
| 5400109 | SESSION_NOT_EXIST | JS API | 会话不存在 | 检查会话状态 |

#### 硬件和超分错误（5400201, 5410002-5410004）

| 错误码 | 错误名称 | 所属阶段 | 常见原因 | 解决方案 |
|--------|---------|---------|---------|---------|
| 5400201 | HARDWARE_FAILED | 硬件 | 硬件失败 | 检查硬件设备 |
| 5410002 | SEEK_CONTINUOUS_UNSUPPORTED | Seek | 不支持连续 seek | 调整 seek 策略 |
| 5410003 | SUPER_RESOLUTION_UNSUPPORTED | 超分 | 超分不支持 | 检查设备超分能力 |
| 5410004 | SUPER_RESOLUTION_NOT_ENABLED | 超分 | 超分未启用 | 启用超分功能 |

#### IO 和网络错误（5411001-5411012）

| 错误码 | 错误名称 | 所属阶段 | 常见原因 | 解决方案 |
|--------|---------|---------|---------|---------|
| 5411001 | IO_CANNOT_FIND_HOST | 数据读取 | 找不到主机（DNS 解析失败） | 检查 URL 和 DNS |
| 5411002 | IO_CONNECTION_TIMEOUT | 数据读取 | 连接超时 | 检查网络连接 |
| 5411003 | IO_NETWORK_ABNORMAL | 数据读取 | 网络异常 | 检查网络状态 |
| 5411004 | IO_NETWORK_UNAVAILABLE | 数据读取 | 网络不可用 | 检查网络连接 |
| 5411005 | IO_NO_PERMISSION | 数据读取 | 无权限 | 检查文件或网络权限 |
| 5411006 | IO_NETWORK_ACCESS_DENIED | 数据读取 | 访问被拒绝 | 检查访问权限 |
| 5411007 | IO_RESOURE_NOT_FOUND | 数据读取 | 资源未找到 | 检查 URL 或文件路径 |
| 5411008 | IO_SSL_CLIENT_CERT_NEEDED | 数据读取 | 需要 SSL 客户端证书 | 配置 SSL 证书 |
| 5411009 | IO_SSL_CONNECT_FAIL | 数据读取 | SSL 连接失败 | 检查 SSL 配置 |
| 5411010 | IO_SSL_SERVER_CERT_UNTRUSTED | 数据读取 | 服务器证书不受信任 | 检查服务器证书 |
| 5411011 | IO_UNSUPPORTTED_REQUEST | 数据读取 | 不支持的请求 | 检查请求类型 |
| 5411012 | IO_CLEARTEXT_NOT_PERMITTED | 数据读取 | 不允许明文传输 | 使用 HTTPS |

---

## 各阶段错误码详解

### 权限和参数错误

#### 201 - NO_PERMISSION
- **阶段**: 权限管理
- **现象**: AccessToken 权限拒绝
- **常见场景**:
  - 未申请必要的权限
  - AccessToken 过期
  - 权限等级不足
- **排查方向**:
  - 检查 module.json5 权限配置
  - 确认 AccessToken 状态
  - 查看权限申请流程
- **解决建议**:
  - 申请必要的权限
  - 刷新 AccessToken
  - 检查权限等级

#### 202 - PERMISSION_DENIED
- **阶段**: 权限管理
- **现象**: 系统 API 权限拒绝
- **常见场景**:
  - 调用系统 API 但未获得授权
  - 应用非系统应用
  - 签名不匹配
- **排查方向**:
  - 检查是否为系统应用
  - 确认应用签名
  - 查看系统 API 调用权限
- **解决建议**:
  - 使用系统签名
  - 申请系统应用授权
  - 使用替代的非系统 API

#### 401 - INVALID_PARAMETER
- **阶段**: JS API
- **现象**: 参数错误
- **常见场景**:
  - URL 格式错误
  - 文件路径不存在
  - 参数类型错误
  - 参数为 null 或 undefined
- **排查方向**:
  - 检查传入参数格式
  - 验证 URL 或文件路径
  - 查看参数校验日志
- **解决建议**:
  - 修正参数格式
  - 检查文件路径是否存在
  - 添加参数校验

#### 801 - UNSUPPORT_CAPABILITY
- **阶段**: JS API
- **现象**: 不支持的能力
- **常见场景**:
  - API 版本不匹配
  - 设备不支持该功能
  - 系统版本过低
- **排查方向**:
  - 检查 API 版本
  - 查看设备能力
  - 确认系统版本
- **解决建议**:
  - 升级系统版本
  - 使用兼容的 API
  - 添加能力检测

### JS API 层错误

#### 5400102 - OPERATE_NOT_PERMIT
- **阶段**: JS API
- **现象**: 操作不允许
- **常见场景**:
  - 在未 Prepare 状态下调用 Play
  - 在 Playing 状态下再次调用 Play
  - 在错误状态下继续操作
  - 状态不匹配
- **排查方向**:
  - 检查播放器当前状态
  - 确认操作时序是否正确
  - 查看状态变化日志
- **解决建议**:
  - 按照正确状态机操作
  - 检查状态转换条件
  - 等待状态就绪后再操作

#### 5400108 - PARAM_ERROR_OUT_OF_RANGE
- **阶段**: JS API
- **现象**: 参数超出范围
- **常见场景**:
  - 播放速度超出范围
  - Seek 位置超出文件长度
  - 参数值超过最大/最小值
- **排查方向**:
  - 检查参数值范围
  - 查看参数限制日志
  - 确认文件时长
- **解决建议**:
  - 调整参数到有效范围
  - 添加参数范围校验
  - 使用 clamp 限制范围

#### 5400109 - SESSION_NOT_EXIST
- **阶段**: JS API
- **现象**: 会话不存在
- **常见场景**:
  - 会话已释放
  - 会话 ID 错误
  - 服务重启导致会话丢失
- **排查方向**:
  - 检查会话状态
  - 确认会话 ID
  - 查看服务状态
- **解决建议**:
  - 重新创建会话
  - 检查会话生命周期
  - 实现会话恢复机制

### 数据读取层错误

#### 5400103 - IO
- **阶段**: 数据读取
- **现象**: IO 错误
- **常见场景**:
  - 文件读取失败
  - 存储设备异常
  - IO 阻塞
- **排查方向**:
  - 检查文件系统状态
  - 查看 IO 错误详情
  - 检查存储设备
- **解决建议**:
  - 检查文件系统
  - 更换存储设备
  - 重启 IO 服务

#### 5400106 - UNSUPPORT_FORMAT
- **阶段**: 数据读取/解封装
- **现象**: 不支持的媒体格式
- **常见场景**:
  - 容器格式不支持（如 .avi, .flv）
  - MIME 类型无法识别
  - 文件头损坏导致格式识别失败
- **排查方向**:
  - 使用 ffprobe 检查文件格式
  - 确认文件扩展名和实际格式一致
  - 检查文件头完整性
- **解决建议**:
  - 转码为支持的格式（.mp4, .mkv, .ts）
  - 重新下载或修复文件

#### 5411001 - IO_CANNOT_FIND_HOST
- **阶段**: 数据读取
- **现象**: 找不到主机（DNS 解析失败）
- **常见场景**:
  - DNS 服务器故障
  - 域名不存在
  - 网络连接问题
  - URL 错误
- **排查方向**:
  - 检查 URL 格式
  - 测试 DNS 解析
  - 检查网络连接
  - 使用 nslookup/dig 工具
- **解决建议**:
  - 修正 URL
  - 更换 DNS 服务器
  - 检查网络连接
  - 使用 IP 地址代替域名

#### 5411002 - IO_CONNECTION_TIMEOUT
- **阶段**: 数据读取
- **现象**: 连接超时
- **常见场景**:
  - 网络延迟过高
  - 服务器响应慢
  - 防火墙阻止
  - 超时时间设置过短
- **排查方向**:
  - 检查网络延迟
  - 测试服务器响应
  - 检查防火墙设置
  - 查看超时配置
- **解决建议**:
  - 增加超时时间
  - 使用 CDN 加速
  - 检查防火墙规则
  - 切换网络

#### 5411003 - IO_NETWORK_ABNORMAL
- **阶段**: 数据读取
- **现象**: 网络异常
- **常见场景**:
  - 网络不稳定
  - 丢包严重
  - 带宽不足
  - 网络拥塞
- **排查方向**:
  - 检查网络稳定性
  - 测试丢包率
  - 检查带宽
  - 查看网络质量
- **解决建议**:
  - 切换稳定网络
  - 降低码率
  - 使用自适应码率
  - 增加缓冲区

#### 5411004 - IO_NETWORK_UNAVAILABLE
- **阶段**: 数据读取
- **现象**: 网络不可用
- **常见场景**:
  - 网络未连接
  - 飞行模式
  - 网络适配器故障
- **排查方向**:
  - 检查网络连接状态
  - 检查飞行模式
  - 检查网络适配器
- **解决建议**:
  - 连接网络
  - 关闭飞行模式
  - 重启网络适配器
  - 提示用户检查网络

#### 5411005 - IO_NO_PERMISSION
- **阶段**: 数据读取
- **现象**: 无权限
- **常见场景**:
  - 文件权限不足
  - 目录权限不足
  - 跨域访问被拒绝
- **排查方向**:
  - 检查文件权限
  - 检查目录权限
  - 检查 CORS 配置
- **解决建议**:
  - 修改文件权限
  - 配置 CORS
  - 使用有权限的账号

#### 5411006 - IO_NETWORK_ACCESS_DENIED
- **阶段**: 数据读取
- **现象**: 访问被拒绝
- **常见场景**:
  - IP 被封禁
  - 需要访问令牌
  - 服务器拒绝访问
  - 访问频率限制
- **排查方向**:
  - 检查 IP 状态
  - 检查访问令牌
  - 查看服务器返回
  - 检查访问频率
- **解决建议**:
  - 使用合法访问令牌
  - 降低访问频率
  - 联系服务器管理员
  - 使用代理

#### 5411007 - IO_RESOURE_NOT_FOUND
- **阶段**: 数据读取
- **现象**: 资源未找到
- **常见场景**:
  - URL 错误（404）
  - 文件路径错误
  - 文件被删除
  - 链接过期
- **排查方向**:
  - 验证 URL 是否正确
  - 确认文件路径存在
  - 检查文件是否被删除
  - 检查链接有效期
- **解决建议**:
  - 修正 URL 或文件路径
  - 恢复被删除的文件
  - 更新链接
  - 检查资源服务器

#### 5411008 - IO_SSL_CLIENT_CERT_NEEDED
- **阶段**: 数据读取
- **现象**: 需要 SSL 客户端证书
- **常见场景**:
  - 未配置客户端证书
  - 证书过期
- **排查方向**:
  - 检查 SSL 配置
  - 检查客户端证书
  - 查看证书有效期
- **解决建议**:
  - 配置客户端证书
  - 更新证书
  - 检查证书链

#### 5411009 - IO_SSL_CONNECT_FAIL
- **阶段**: 数据读取
- **现象**: SSL 连接失败
- **常见场景**:
  - SSL 版本不匹配
  - 加密算法不支持
  - 握手失败
- **排查方向**:
  - 检查 SSL 版本
  - 检查加密算法
  - 查看 SSL 握手日志
- **解决建议**:
  - 更新 SSL 版本
  - 使用支持的加密算法
  - 检查 SSL 配置

#### 5411010 - IO_SSL_SERVER_CERT_UNTRUSTED
- **阶段**: 数据读取
- **现象**: 服务器证书不受信任
- **常见场景**:
  - 自签名证书
  - 证书链不完整
  - 证书过期
  - 域名不匹配
- **排查方向**:
  - 检查服务器证书
  - 检查证书链
  - 查看证书有效期
  - 检查域名匹配
- **解决建议**:
  - 安装信任证书
  - 更新证书
  - 修正域名
  - 配置证书验证策略

#### 5411011 - IO_UNSUPPORTTED_REQUEST
- **阶段**: 数据读取
- **现象**: 不支持的请求
- **常见场景**:
  - HTTP 方法不支持
  - 请求协议不支持
  - 请求格式错误
- **排查方向**:
  - 检查 HTTP 方法
  - 检查请求协议
  - 查看请求格式
- **解决建议**:
  - 使用支持的 HTTP 方法
  - 使用支持的协议
  - 修正请求格式

#### 5411012 - IO_CLEARTEXT_NOT_PERMITTED
- **阶段**: 数据读取
- **现象**: 不允许明文传输
- **常见场景**:
  - 系统配置禁止 HTTP
  - 安全策略要求 HTTPS
  - 明文传输被拦截
- **排查方向**:
  - 检查网络安全配置
  - 检查安全策略
  - 查看系统日志
- **解决建议**:
  - 使用 HTTPS
  - 配置网络安全策略
  - 更新 URL 为 HTTPS

### 系统和硬件错误

#### 5400105 - SERVICE_DIED
- **阶段**: 系统
- **现象**: 媒体服务死亡
- **常见场景**:
  - 媒体服务崩溃
  - 系统资源不足
  - 服务被系统杀死
  - 服务异常退出
- **排查方向**:
  - 检查媒体服务状态
  - 查看系统日志
  - 检查系统资源
  - 查看崩溃堆栈
- **解决建议**:
  - 重启媒体服务
  - 重启设备
  - 释放系统资源
  - 升级系统版本

#### 5400201 - HARDWARE_FAILED
- **阶段**: 硬件
- **现象**: 硬件失败
- **常见场景**:
  - 硬件解码器故障
  - 硬件加速失败
  - 设备硬件异常
  - 驱动程序错误
- **排查方向**:
  - 检查硬件设备状态
  - 查看驱动日志
  - 检查硬件加速配置
  - 查看系统硬件信息
- **解决建议**:
  - 切换到软件解码
  - 更新驱动程序
  - 重启设备
  - 联系硬件厂商

### 音频错误

#### 5400107 - AUDIO_INTERRUPTED
- **阶段**: 音频
- **现象**: 音频中断
- **常见场景**:
  - 音频焦点被抢占
  - 来电打断
  - 蓝牙断开
  - 音频设备切换
  - 系统音频策略中断
- **排查方向**:
  - 检查音频焦点状态
  - 查看音频策略日志
  - 检查音频设备状态
  - 查看中断原因
- **解决建议**:
  - 处理音频焦点
  - 实现音频中断恢复
  - 检查音频设备连接
  - 配置音频策略

### Seek 和超分错误

#### 5410002 - SEEK_CONTINUOUS_UNSUPPORTED
- **阶段**: Seek
- **现象**: 不支持连续 seek
- **常见场景**:
  - 直播流不支持 seek
  - 某些格式不支持精确定位
  - 网络流不支持随机访问
  - 连续 seek 操作过快
- **排查方向**:
  - 检查播放类型（直播/点播）
  - 检查媒体格式
  - 查看 seek 操作日志
  - 检查网络流类型
- **解决建议**:
  - 避免在直播中 seek
  - 降低 seek 频率
  - 使用支持的格式
  - 添加 seek 能力检测

#### 5410003 - SUPER_RESOLUTION_UNSUPPORTED
- **阶段**: 超分
- **现象**: 超分不支持
- **常见场景**:
  - 设备不支持超分
  - 视频分辨率超出超分范围
  - 编码格式不支持超分
  - 系统版本过低
- **排查方向**:
  - 检查设备超分能力
  - 查看视频分辨率
  - 检查编码格式
  - 检查系统版本
- **解决建议**:
  - 检查设备能力
  - 使用支持的分辨率
  - 升级系统版本
  - 关闭超分功能

#### 5410004 - SUPER_RESOLUTION_NOT_ENABLED
- **阶段**: 超分
- **现象**: 超分未启用
- **常见场景**:
  - 未配置超分参数
  - 超分功能未开启
  - 超分配置错误
- **排查方向**:
  - 检查超分配置
  - 查看超分参数
  - 检查功能开关
- **解决建议**:
  - 配置超分参数
  - 启用超分功能
  - 检查配置正确性

### 通用错误

#### 5400101 - NO_MEMORY
- **阶段**: 通用
- **现象**: 内存不足
- **常见场景**:
  - 设备内存不足
  - 内存泄漏
  - 分配过大缓冲区
  - 同时运行多个播放实例
- **排查方向**:
  - 检查设备内存占用
  - 查看内存分配日志
  - 检查是否有内存泄漏
  - 查看播放实例数量
- **解决建议**:
  - 释放其他应用内存
  - 降低播放分辨率
  - 减小缓冲区大小
  - 修复内存泄漏
  - 减少播放实例

#### 5400104 - TIMEOUT
- **阶段**: 通用
- **现象**: 操作超时
- **常见场景**:
  - 网络读取超时
  - 解封装超时
  - 解码超时
  - 等待资源超时
- **排查方向**:
  - 检查网络速度
  - 检查文件读取性能
  - 查看各阶段耗时
  - 检查超时配置
- **解决建议**:
  - 增加超时时间
  - 优化网络或文件读取
  - 降低码率或分辨率
  - 检查资源可用性

---

## 错误定位流程

### 标准定位步骤

```
┌─────────────────────────────────────────────────────────────┐
│ 0. 检测AVPlayer使用情况                                      │
│    - 搜索: PrintCaller.*av_codec_service/HCODEC             │
│    - 检查调用链是否包含"player"                              │
│    - 确定分析路径（AVPlayer vs 直接解码器）                  │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 1. 识别错误回调                                              │
│    - 搜索: OnErrorCb OR PLAYER_STATE_ERROR                  │
│    - 提取错误码和错误信息                                    │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. 查询错误码表                                              │
│    - 确定错误类型和所属阶段                                  │
│    - 了解常见原因和解决方案                                  │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. 查看错误上下文                                            │
│    - 查看错误日志前后 5-10 行                                │
│    - 分析错误发生时的状态                                    │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. 定位失败阶段                                              │
│    - 根据错误码确定阶段                                      │
│    - 结合上下文日志验证                                      │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. 分析根本原因                                              │
│    - 结合媒体信息、环境信息                                  │
│    - 排除法分析可能原因                                      │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. 提供解决建议                                              │
│    - 给出具体的解决方案                                      │
│    - 提供验证方法                                            │
└─────────────────────────────────────────────────────────────┘
```

### 快速定位决策树

```
开始
  ↓
检测是否使用AVPlayer？（搜索PrintCaller）
  ├─ 调用链包含"player" → 使用AVPlayer，进入AVPlayer分析流程
  └─ 调用链直接到avcodec → 未使用AVPlayer，进入解码器分析流程
           ↓
识别到 OnErrorCb？
  ├─ 是 → 提取错误码
  │        ↓
  │     查询错误码表
  │        ↓
  │     确定错误类型和阶段
  │        ↓
  │     查看错误上下文
  │        ↓
  │     分析根本原因
  │        ↓
  │     提供解决建议
  │
  └─ 否 → 搜索 PLAYER_STATE_ERROR
           ↓
        有明确错误信息？
          ├─ 是 → 分析错误信息
          └─ 否 → 检查各阶段异常日志
```

---

## 常见错误码排查

### 按错误码索引

#### 5400101 - NO_MEMORY
**错误日志示例**:
```
11-18 22:04:58.940 18389 18389 E A000FF/eboard:EngineServiceAbility:16/ThemeEngine: [6.1.6-305]AvPlayerProxy --> createAVPlayer fail, code: 5400101, message: The instance or memory has reached the upper limit, please recycle background playback
```

**排查步骤**:
1. 检查设备内存占用
2. 查看内存分配日志
3. 检查是否有内存泄漏

**解决建议**:
- 释放内存
- 降低播放分辨率
- 减小缓冲区大小
- 修复内存泄漏

#### 5400102 - OPERATE_NOT_PERMIT
**错误日志示例**:
```
04-06 18:12:08.784 23495 23495 E C02B2B/com.tencent.wechat/AVPlayerCallback: #787 OnErrorCb:errorCode 5400102, errorMsg Operate Not Permit: current state is not idle, unsupport set url
```

**排查步骤**:
1. 检查播放器当前状态
2. 确认操作时序是否正确
3. 查看状态变化日志

**解决建议**:
- 按照正确状态机操作
- 检查状态转换条件
- 等待状态就绪后再操作

#### 5400103 - IO
**错误日志示例**:
```
errorcode: 5400103, error msg : IO Error: AUD_OUTPUT_ERR-null-unsupport interface, audio render failed.
```

**排查步骤**:
1. 检查文件系统状态
2. 查看 IO 错误详情
3. 检查存储设备

**解决建议**:
- 检查文件系统
- 更换存储设备
- 重启 IO 服务

#### 5400104 - TIMEOUT
**错误日志示例**:
```
onPlayErr errorCode:5400104, song: ***-66709373)-1PLAYFULL-Qundefined, msg:time out for set datasource
```

**排查步骤**:
1. 检查网络速度
2. 检查文件读取性能
3. 查看各阶段耗时

**解决建议**:
- 增加超时时间
- 优化网络或文件读取
- 降低码率或分辨率

#### 5400105 - SERVICE_DIED
**错误日志示例**:
```
error code: 5400105, error msg : Service Died: mediaserver is died, please create a new playback instance
```

**排查步骤**:
1. 检查媒体服务状态
2. 查看系统日志
3. 检查系统资源
4. 查看崩溃堆栈

**解决建议**:
- 重启媒体服务
- 重启设备
- 释放系统资源
- 升级系统版本

#### 5400106 - UNSUPPORT_FORMAT
**错误日志示例**:
```
OnErrorCb:errorCode 5400106, errorMsg Unsupported Format: unsupport interface, unsupport video params(other params)
```

**排查步骤**:
1. 使用 ffprobe 检查文件格式
   ```bash
   ffprobe -i file.mp4 -show_format -show_streams
   ```
2. 确认容器格式和编码格式
3. 检查文件头是否完整

**解决建议**:
- 转码为支持的格式（.mp4, .mkv, .ts）
- 重新下载或修复文件

#### 5400107 - AUDIO_INTERRUPTED
**错误日志示例**:
```
05-13 18:03:48.000 ... OnErrorCb:errorCode 5400107
05-13 18:03:48.010 ... AUDIO_INTERRUPTED: audio focus lost
```

**排查步骤**:
1. 检查音频焦点状态
2. 查看音频策略日志
3. 检查音频设备状态
4. 查看中断原因

**解决建议**:
- 处理音频焦点
- 实现音频中断恢复
- 检查音频设备连接
- 配置音频策略

#### 5411001 - IO_CANNOT_FIND_HOST
**错误日志示例**:
```
08-27 14:04:33.515 36442 36517 E C02B2B/com.beike.hongmeng/AVPlayerCallback: #787 OnErrorCb:errorCode 5411001, errorMsg IO Cannot Find Host: IO error, IO can not find host
```

**排查步骤**:
1. 检查 URL 格式
2. 测试 DNS 解析
   ```bash
   nslookup example.com
   ```
3. 检查网络连接
4. 查看网络配置

**解决建议**:
- 修正 URL
- 更换 DNS 服务器
- 检查网络连接
- 使用 IP 地址代替域名

#### 5411002 - IO_CONNECTION_TIMEOUT
**错误日志示例**:
```
OnErrorCb:errorCode 5411002, errorMsg IO Connection Timeout: IO error, IO connection timeout
```

**排查步骤**:
1. 检查网络延迟
   ```bash
   ping example.com
   ```
2. 测试服务器响应
3. 检查防火墙设置
4. 查看超时配置

**解决建议**:
- 增加超时时间
- 使用 CDN 加速
- 检查防火墙规则
- 切换网络

#### 5411004 - IO_NETWORK_UNAVAILABLE
**错误日志示例**:
```
05-13 18:03:48.000 ... OnErrorCb:errorCode 5411004
05-13 18:03:48.010 ... IO_NETWORK_UNAVAILABLE: no network
```

**排查步骤**:
1. 检查网络连接状态
2. 检查飞行模式
3. 检查网络适配器

**解决建议**:
- 连接网络
- 关闭飞行模式
- 重启网络适配器
- 提示用户检查网络

#### 5411007 - IO_RESOURE_NOT_FOUND
**错误日志示例**:
```
onError 5411007 IO Resource Not Found: IO error, IO resource not found
```

**排查步骤**:
1. 验证 URL 是否正确
2. 确认文件路径存在
3. 检查文件是否被删除
4. 检查链接有效期

**解决建议**:
- 修正 URL 或文件路径
- 恢复被删除的文件
- 更新链接
- 检查资源服务器

#### 5400201 - HARDWARE_FAILED
**错误日志示例**:
```
05-13 18:03:48.000 ... OnErrorCb:errorCode 5400201
05-13 18:03:48.010 ... HARDWARE_FAILED: decoder init failed
```

**排查步骤**:
1. 检查硬件设备状态
2. 查看驱动日志
3. 检查硬件加速配置
4. 查看系统硬件信息

**解决建议**:
- 切换到软件解码
- 更新驱动程序
- 重启设备
- 联系硬件厂商

---



## 错误码快速索引

### 按现象查找

| 现象 | 可能错误码 | 排查方向 |
|------|-----------|---------|
| 播放失败 | 5400101, 5400103, 5400106, 5400201 | 检查内存、状态、格式、硬件 |
| 网络问题 | 5411001-5411012, 5400103 | 检查网络连接、DNS、SSL |
| 音频中断 | 5400107 | 检查音频焦点和设备 |
| 超时 | 5400104, 5411002 | 检查网络和性能 |
| 内存不足 | 5400101 | 释放内存或降低画质 |
| 状态异常 | 5400102 | 检查播放器状态机 |
| 参数错误 | 201, 202, 401, 801 | 检查传入参数和权限 |
| Seek 失败 | 5410002 | 检查是否支持随机访问 |
| 超分失败 | 5410003, 5410004 | 检查设备能力和配置 |

### 按阶段查找

| 阶段 | 可能错误码 |
|------|-----------|
| 权限和参数 | 201, 202, 401, 801 |
| JS API | 5400102, 5400108, 5400109 |
| 数据读取 | 5400103, 5400106, 5411001-5411012 |
| 系统和硬件 | 5400105, 5400201 |
| 音频 | 5400107 |
| Seek | 5410002 |
| 超分 | 5410003, 5410004 |
| 通用 | 5400101, 5400104 |

---

## 附录

### 工具推荐
- ffprobe - 媒体文件分析
- VLC Media Player - 格式兼容性测试
- Wireshark - 网络问题分析

### 联系支持
如遇到未涵盖的错误码或复杂问题，请收集以下信息寻求支持：
1. 完整的 hilog 日志
2. 媒体文件信息（使用 ffprobe）
3. 设备和系统信息
4. 错误复现步骤
# 音视频采集技术
 
> 录制框架的音频和视频数据采集机制
 
## 解决的问题（Problem）
 
| 子维度 | 内容 |
| --- | -- |
| 业务痛点 | 音频和视频数据来源多样（麦克风/摄像头/屏幕/外部数据源），需要统一抽象和灵活接入 |
| 技术目标 | 提供统一的Source抽象，支持多种音视频输入源，通过Surface/数据源接口接收数据 |
| 适用场景 | 麦克风录音、摄像头录像、屏幕录制、外部PCM数据录音 |
 
## 核心概念与术语（Concepts）
 
| 子维度 | 内容 |
| --- | -- |
| 关键术语 | AudioSourceType（音频源类型）、VideoSourceType（视频源类型）、AudioCaptureFilter（音频采集Filter）、VideoCaptureFilter（视频采集Filter）、AudioDataSourceFilter（外部音频数据源Filter） |
| 角色定义 | AudioCaptureFilter封装AudioCapturer采集PCM；VideoCaptureFilter管理Camera Surface接收视频帧；AudioDataSourceFilter接收外部IAudioDataSource数据 |
| 核心对象 | AudioCapturer（Audio框架）、Surface（显示/Buffer框架）、IAudioDataSource（外部数据源接口） |
 
## 原理（Principles）
 
| 子维度 | 内容 |
| --- | -- |
| 核心机制 | 音频：AudioCaptureFilter创建AudioCapturer实例，采集PCM数据送入Pipeline；视频：VideoCaptureFilter持有Producer Surface，Camera写入帧数据，Filter读取后送入编码器 |
| 架构组成 | 音频链路：AudioCapturer → AudioCaptureFilter → AudioEncoderFilter；视频链路：Camera Surface → [WaterMarkFilter] → SurfaceEncoderFilter |
| 关键流程 | 音频采集：1.AudioCaptureFilter::SetParam配置采样率/声道/格式 2.Start创建并启动AudioCapturer 3.OnLoop读PCM帧送入下游；视频采集：1.GetSurface返回Producer Surface 2.Camera输出帧到Surface 3.SurfaceEncoderFilter读帧送入下游 |
| 数据/控制流 | 音频数据流：AudioCapturer → PCM Buffer → AudioCaptureFilter → AVBufferQueue → AudioEncoderFilter；视频数据流：Camera → Surface Buffer → SurfaceEncoderFilter → AVBufferQueue → Muxer |
 
## 使用方式（Usage）
 
| 子维度 | 内容 |
| --- | -- |
| 接入条件 | 通过Pipeline自动管理 |
| 配置步骤 | 音频：SetAudioSource(MIC) → Configure(采样率/声道/码率)；视频：SetVideoSource(SURFACE_ES) → GetSurface → Camera绑定Surface |
| 核心API | SetAudioSource / SetVideoSource / GetSurface / SetAudioDataSource |
| 典型流程 | 录音：SetAudioSource(AUDIO_MIC) → Configure(audioParams) → Prepare → Start；录像：SetVideoSource(VIDEO_SURFACE) → SetAudioSource(AUDIO_MIC) → GetSurface → Camera绑定 → Prepare → Start |
 
## 代码关联（Code）
 
| 子维度 | 内容 |
| --- | -- |
| 核心类/接口 | AudioCaptureFilter、VideoCaptureFilter、AudioDataSourceFilter |
| 关键配置文件 | av_codec/services/media_engine/filters/BUILD.gn |
| 代码结构 | AudioCaptureFilter注册名"builtin.recorder.audio_capture"；SurfaceEncoderFilter注册名"builtin.recorder.surface_encoder" |
 
## 约束与限制（Constraints）
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | 音频采集需MICROPHONE权限；视频采集需CAMERA权限；Screen录屏需对应系统权限 |
| 环境依赖 | 依赖Audio框架的AudioCapturer；依赖Surface/Buffer框架 |
| 性能约束 | 音频采集延迟受AudioCapturer影响；视频采集帧率受Camera输出影响 |
| 安全约束 | 音频源类型校验：CheckAudioSourceType仅允许合法的AudioSourceType |
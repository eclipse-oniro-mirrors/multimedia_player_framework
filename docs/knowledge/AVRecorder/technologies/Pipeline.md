# Pipeline技术
 
> Histreamer Filter Pipeline编排机制
 
## 解决的问题（Problem）
 
| 子维度 | 内容 |
| --- | -- |
| 业务痛点 | 音视频录制涉及采集→编码→封装多个阶段，各阶段需要灵活组合和替换，硬编码流程无法适应多样化录制场景 |
| 技术目标 | 提供一种可插拔、可编排的数据流框架，支持灵活组合不同Filter完成录制链路 |
| 适用场景 | 纯音频录制、音视频录制、带水印录制、录屏+元数据录制等不同链路组合 |
 
## 核心概念与术语（Concepts）
 
| 子维度 | 内容 |
| --- | -- |
| 关键术语 | Filter（数据处理器）、Pipeline（Filter容器和编排器）、StreamType（数据流类型：AUDIO/VIDEO/META） |
| 角色定义 | Pipeline负责Filter生命周期和链接；Filter负责数据处理；EventReceiver负责事件上报；FilterCallback负责处理完成回调 |
| 核心对象 | Pipeline对象、Filter对象、AVBufferQueue（Filter间数据传递通道） |
 
## 原理（Principles）
 
| 子维度 | 内容 |
| --- | -- |
| 核心机制 | Filter是数据处理的基本单元，Pipeline将Filter按数据流方向链接，数据通过AVBufferQueue在Filter间传递 |
| 架构组成 | Pipeline → [AudioCaptureFilter → AudioEncoderFilter → MuxerFilter] 音频链路；[(WaterMarkFilter) → SurfaceEncoderFilter → MuxerFilter] 视频链路 |
| 关键流程 | 1.HiRecorderImpl创建Pipeline 2.根据Source类型AddFilter 3.LinkFilters建立数据通道 4.Prepare启动各Filter 5.Start驱动Pipeline运行 6.Stop/Reset销毁Pipeline |
| 数据/控制流 | 控制流：HiRecorderImpl → Pipeline → Filter（Start/Stop/Pause命令）；数据流：上游Filter → AVBufferQueue → 下游Filter |
 
## 使用方式（Usage）
 
| 子维度 | 内容 |
| --- | -- |
| 接入条件 | 通过HiRecorderImpl间接使用，不直接操作Pipeline |
| 配置步骤 | 1.SetVideoSource/SetAudioSource 2.SetOutputFormat 3.Configure各源参数 4.Prepare自动构建Pipeline |
| 核心API | Pipeline::AddFilter / Pipeline::LinkFilters / Pipeline::Start / Pipeline::Pause / Pipeline::Resume / Filter::SetParam / Filter::SendEos |
| 典型流程 | 音频录制Pipeline：AudioCaptureFilter(采集) → AudioEncoderFilter(编码) → MuxerFilter(封装) |
 
## 代码关联（Code）
 
| 子维度 | 内容 |
| --- | -- |
| 核心类/接口 | Pipeline::Pipeline、Pipeline::Filter、Pipeline::FilterCallback、Pipeline::EventReceiver |
| 关键配置文件 | services/engine/histreamer/recorder/BUILD.gn |
| 代码结构 | HiRecorderImpl持有pipeline_成员，BuildPipeline/BuildVideoPipeline/BuildWatermarkPipeline构建不同链路 |
 
## 约束与限制（Constraints）
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | Pipeline构建后不可动态增删Filter，需Reset后重建 |
| 环境依赖 | 依赖Histreamer基础库 |
| 性能约束 | Pipeline Prepare涉及Filter创建和链接，耗时操作 |
| 安全约束 | Filter间通过AVBufferQueue传递数据，避免共享内存 |
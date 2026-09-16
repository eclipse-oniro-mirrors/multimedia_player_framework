# HiRecorder
 
> 录制引擎层的核心实现，基于Histreamer Pipeline框架
 
## 实体概念
 
| 子维度 | 内容 |
| --- | -- |
| 实体名称 | HiRecorder（HiRecorderImpl，录制引擎） |
| 实体定义 | IRecorderEngine接口的实现类，基于Histreamer Pipeline框架构建录制数据流链路 |
| 核心特征 | Pipeline编排、Filter生命周期管理、Source抽象（音频/视频/元数据）、软硬件水印支持 |
| 类型/分类 | 引擎层组件 |
 
## 上下文与场景
 
| 子维度 | 内容 |
| --- | -- |
| 使用场景 | 所有录制Pipeline的构建与执行 |
| 角色与参与方 | RecorderServer（调用者）、各Filter（执行者）、IRecorderEngineObs（观察者） |
| 生命周期 | Init → SetSource → SetOutputFormat → Configure → Prepare → Start → Pause/Resume → Stop → Reset |
| 交互流程 | 1.Server调用SetVideoSource/SetAudioSource 2.调用SetOutputFormat锁定源 3.Configure各源参数 4.Prepare构建Pipeline并启动 5.Start驱动Pipeline运行 6.Stop/Reset销毁Pipeline |
| 状态流转 | StateId::INIT → RECORDING_SETTING → READY → RECORDING ↔ PAUSE；可转入ERROR |
| 异常处理路径 | Filter上报Error事件→OnEvent→obs_->OnError→Server回调应用 |
 
## 规格与约束
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | Pipeline构建后不可动态修改Filter；最多1个视频源+1个音频源 |
| 业务规则 | SetOutputFormat后不再接受Source设置；Configure必须在SetOutputFormat后 |
| 性能约束 | Pipeline Prepare涉及Filter创建和链接，耗时需异步处理 |
 
## 知识关联
 
| 子维度 | 内容 |
| --- | -- |
| 上层依赖 | IRecorderEngine接口、Histreamer Pipeline框架 |
| 下游影响 | AudioCaptureFilter、AudioEncoderFilter、VideoCaptureFilter、SurfaceEncoderFilter、WaterMarkFilter、MuxerFilter、MetaDataFilter |
| 平级关联 | HiPlayer（播放引擎，同样基于Pipeline） |
| 概念对比 | HiRecorder vs RecorderServer：HiRecorder是引擎实现，专注于Pipeline；Server是服务管理，专注于状态和配置 |
 
## 数据模型
 
| 子维度 | 内容 |
| --- | -- |
| 核心数据结构 | audioEncFormat_/videoEncFormat_/muxerFormat_（Meta格式描述）|
| 数据流转路径 | Server Configure → HiRecorder Configure → 各Filter SetParam |
 
## 代码与符号
 
| 子维度 | 内容 |
| --- | -- |
| 核心API/类 | HiRecorderImpl |
| 核心符号映射 | Init → HiRecorderImpl::Init; BuildPipeline → HiRecorderImpl::BuildPipeline; BuildWatermarkPipeline → HiRecorderImpl::BuildWatermarkPipeline |
| 关键配置文件 | services/engine/histreamer/recorder/BUILD.gn |
| 核心代码片段 | Pipeline构建：pipeline_->AddFilter(filter) → pipeline_->LinkFilters() → pipeline_->Start() |
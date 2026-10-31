# 封装器（Muxer）
 
> 音视频封装写入文件
 
## 解决的问题（Problem）
 
| 子维度 | 内容 |
| --- | -- |
| 业务痛点 | 编码后的音视频裸流需要按容器格式组织写入文件，不同格式（MP4/M4A/AAC等）的封装逻辑不同 |
| 技术目标 | 提供统一的封装接口，支持多种容器格式，管理音视频轨道和数据写入 |
| 适用场景 | 所有录制场景的文件输出阶段 |
 
## 核心概念与术语（Concepts）
 
| 子维度 | 内容 |
| --- | -- |
| 关键术语 | MuxerFilter（封装Filter）、MediaMuxer（底层封装器）、OutputFormat（输出格式）、DataSinkFd（fd写入封装） |
| 角色定义 | MuxerFilter是Pipeline中的封装节点；MediaMuxer是实际封装引擎；DataSinkFd是文件写入抽象 |
| 核心对象 | MuxerFilter、MediaMuxer、AVBufferQueue（接收编码数据） |
 
## 原理（Principles）
 
| 子维度 | 内容 |
| --- | -- |
| 核心机制 | MuxerFilter在Pipeline中作为末端节点，接收编码后的音视频数据，通过MediaMuxer按容器格式封装写入fd |
| 架构组成 | 音频编码器/视频编码器 → AVBufferQueue → MuxerFilter → MediaMuxer → DataSinkFd → 文件 |
| 关键流程 | 1.MuxerFilter::SetParam设置输出格式和fd 2.AddTrack添加音视频轨道 3.Start开始封装 4.OnBufferFilled持续写入编码数据 5.SendEos结束封装 |
| 数据/控制流 | 数据流：Encoder → MuxerFilter → MediaMuxer → File；控制流：Pipeline → MuxerFilter（Start/Stop） |
 
## 使用方式（Usage）
 
| 子维度 | 内容 |
| --- | -- |
| 接入条件 | 通过Pipeline自动使用，不直接操作 |
| 配置步骤 | Engine Configure时设置OutputFormat和OutputFd → MuxerFilter自动初始化 |
| 核心API | MuxerFilter::SetParam / MuxerFilter::Start / MuxerFilter::Stop / MuxerFilter::SendEos |
| 典型流程 | MP4封装：添加H264视频轨道 + AAC音频轨道 → 写入编码数据 → 文件尾 |
 
## 代码关联（Code）
 
| 子维度 | 内容 |
| --- | -- |
| 核心类/接口 | MuxerFilter、MediaMuxer、DataSinkFd |
| 关键配置文件 | av_codec/services/media_engine/filters/BUILD.gn |
| 代码结构 | MuxerFilter注册名"builtin.recorder.muxer"；格式映射表FORMAT_TABLE：MPEG_4→MP4, M4A→M4A, AMR→AMR, MP3→MP3, WAV→WAV, AAC→AAC |
 
## 约束与限制（Constraints）
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | 输出格式必须在Prepare前确定；fd必须可写 |
| 环境依赖 | 依赖MediaMuxer库 |
| 性能约束 | 音视频PTS同步阈值200ms（SYNC_THRESHOLD_US） |
| 安全约束 | fd由应用传入，框架不负责文件权限管理 |
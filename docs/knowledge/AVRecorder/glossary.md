# 术语表
> 只说明模型不知道的术语，常识类不要写

## AVRecorder
：AVRecorder是录制框架对应用暴露的JS/ArkTS API对象，概念类型为实体，提供音视频录制全生命周期管理能力，包含prepare/start/pause/resume/stop/reset/release等操作和stateChange/error等事件回调。完整信息指向 [AVRecorder](entities/AVRecorder.md)

## HiRecorder
：HiRecorder（HiRecorderImpl）是录制引擎层的核心实现类，概念类型为实体，基于Histreamer Pipeline框架构建录制数据流链路，管理AudioCapture/AudioEncoder/VideoCapture/VideoEncoder/WaterMark/Muxer等Filter的生命周期和协作。完整信息指向 [HiRecorder](entities/HiRecorder.md)

## RecorderServer
：RecorderServer是录制服务端实现，概念类型为实体，运行在media_service进程中，实现IRecorderService接口，负责配置管理、状态机、回调分发、DFX上报，协调Engine执行录制操作。完整信息指向 [RecorderServer](entities/RecorderServer.md)

## SourceId
：SourceId是录制源的唯一标识，概念类型为实体，由SetVideoSource/SetAudioSource/SetMetaSource返回，用于后续配置该源的相关参数。采用掩码编码：0x100系列为视频源、0x200系列为音频源、0x300系列为元数据源。完整信息指向 [SourceId](entities/SourceId.md)

## Pipeline
：Pipeline是Histreamer框架的核心编排机制，概念类型为技术，将Filter按数据流方向连接，管理Filter的创建、链接、启停和销毁。录制场景下Pipeline由HiRecorderImpl构建。完整信息指向 [Pipeline技术](technologies/Pipeline.md)

## WaterMark
：WaterMark是录制水印机制，概念类型为实体，支持在视频帧上叠加水印图片。分为硬件水印（通过编码器内嵌）和软件水印（通过OpenGL渲染）两种模式，支持融合叠加，最多5个水印。完整信息指向 [WaterMark](entities/WaterMark.md)

## MuxerFilter
：MuxerFilter是封装器Filter，概念类型为实体，负责将编码后的音视频数据按容器格式（MP4/M4A/AAC等）封装写入文件，管理音视频轨道的添加和数据写入。完整信息指向 [Muxer](technologies/Muxer.md)

## AVRecorderConfig
：AVRecorderConfig是录制配置数据结构，概念类型为实体，包含音频源类型、视频源类型、元数据源类型、音视频Profile（编码格式/码率/采样率/分辨率/帧率）、输出URL、旋转角度、最大时长、地理位置、文件生成模式等。完整信息指向 [AVRecorderConfig](entities/AVRecorderConfig.md)

## IPC Proxy/Stub
：IPC Proxy/Stub是OHOS进程间通信机制，概念类型为技术，RecorderClient通过Proxy发送请求，RecorderServer通过Stub接收请求，回调通过RecorderListenerProxy/Stub反向传递。完整信息指向 [IPC通信](technologies/IPCLayer.md)

## FileGenerationMode
：文件生成模式，概念类型为实体枚举，APP_CREATE表示应用自行创建文件fd传入，AUTO_CREATE表示框架通过MediaLibraryAdapter自动创建媒体资产文件。默认APP_CREATE。

## AVRecorderState
：录制状态枚举，包含idle/prepared/started/paused/stopped/released/error七种状态，不同状态下允许的操作集合由stateCtrlList定义。

## DUMMY_SOURCE_ID
：值为0的虚拟源ID，概念类型为技术常量，用于Configure/SetParameter中配置与具体Source无关的全局参数（如MaxDuration、OutputFormat等）。

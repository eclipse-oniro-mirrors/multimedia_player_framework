# 水印融合技术
 
> 软硬件水印融合机制
 
## 解决的问题（Problem）
 
| 子维度 | 内容 |
| --- | -- |
| 业务痛点 | 视频录制需要叠加水印（Logo/时间戳/合规标识），硬件水印性能好但灵活性差，软件水印灵活但性能差，需要融合两者优势 |
| 技术目标 | 支持硬件水印和软件水印同时叠加，取长补短，满足不同场景需求 |
| 适用场景 | 录屏+水印、视频录制+时间水印、合规录制+Logo水印 |
 
## 核心概念与术语（Concepts）
 
| 子维度 | 内容 |
| --- | -- |
| 关键术语 | 硬件水印（编码器内嵌水印）、软件水印（OpenGL渲染叠加）、WaterMarkFilter（软件水印Filter）、水印融合（软硬件同时叠加） |
| 角色定义 | 应用提供水印图片和位置；HiRecorderImpl管理水印模式；WaterMarkFilter执行软件水印渲染；SurfaceEncoderFilter执行硬件水印叠加 |
| 核心对象 | WaterMarkFilter（OpenGL渲染管线）、AVBuffer（水印像素数据）、WatermarkConfig（位置配置） |
 
## 原理（Principles）
 
| 子维度 | 内容 |
| --- | -- |
| 核心机制 | 硬件水印：水印图片传入编码器，编码时在硬件层面叠加到视频帧；软件水印：WaterMarkFilter通过OpenGL着色器将水印纹理叠加到视频帧上 |
| 架构组成 | 视频链路：Camera Surface → [WaterMarkFilter(软件水印)] → SurfaceEncoderFilter(+硬件水印) → MuxerFilter |
| 关键流程 | 1.IsWatermarkSupported查询硬件水印能力 2.SetWatermark设置硬件水印数据到编码器 3.AddWatermark添加软件水印到WaterMarkFilter 4.录制时两种水印叠加到同一帧 |
| 数据/控制流 | 控制流：HiRecorderImpl→WaterMarkFilter/SetEncoderAdapter；数据流：水印AVBuffer→Filter/Encoder→叠加到视频帧 |
 
## 使用方式（Usage）
 
| 子维度 | 内容 |
| --- | -- |
| 接入条件 | 视频录制场景，处于prepared状态后 |
| 配置步骤 | 1.调用IsWatermarkSupported查询硬件水印支持 2.调用SetWatermark(PixelMap+WatermarkConfig)设置硬件水印 3.调用AddWatermark(ArrayBuffer+WatermarkConfiguration)添加软件水印 |
| 核心API | IsWatermarkSupported / SetWatermark / AddWatermark |
| 典型流程 | Prepared → IsWatermarkSupported(true) → SetWatermark(logo) → AddWatermark(timestamp, position) → Start录制 |
 
## 代码关联（Code）
 
| 子维度 | 内容 |
| --- | -- |
| 核心类/接口 | WaterMarkFilter、HiRecorderImpl::BuildWatermarkPipeline / BuildHardWatermarkPipeline / BuildSoftWatermarkPipeline |
| 代码结构 | WaterMarkFilter使用OpenGL顶点/片段着色器渲染水印纹理；支持旋转（0/90/180/270度）适配视频方向 |
 
## 约束与限制（Constraints）
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | 最多5个水印；单水印数据不超80MB；硬件水印依赖编码器能力 |
| 环境依赖 | 软件水印需OpenGL ES环境；硬件水印需编码器支持 |
| 性能约束 | 软件水印使用GPU渲染，帧处理延迟增加约1-3ms |
| 安全约束 | 水印位置不可超出视频帧范围 |
# WaterMark
 
> 录制水印机制，支持软硬件水印融合
 
## 实体概念
 
| 子维度 | 内容 |
| --- | -- |
| 实体名称 | WaterMark（水印） |
| 实体定义 | 在视频录制过程中叠加到视频帧上的图片水印，支持硬件水印（编码器内嵌）和软件水印（OpenGL渲染）两种模式 |
| 核心特征 | 软硬件融合、最多5个水印、OpenGL ES渲染、支持位置配置（top/left偏移）|
| 类型/分类 | 硬件水印（SetWatermark，编码器层面叠加）、软件水印（AddWatermark，OpenGL渲染叠加） |
 
## 上下文与场景
 
| 子维度 | 内容 |
| --- | -- |
| 使用场景 | 视频录制时叠加时间戳/Logo/合规标识；录屏时叠加水印 |
| 角色与参与方 | 应用（设置水印）、HiRecorderImpl（管理水印模式）、WaterMarkFilter（软件水印渲染）、SurfaceEncoderFilter（硬件水印叠加）|
| 生命周期 | Prepared后设置 → 录制期间持续叠加 → Stop后清除 |
| 交互流程 | 1.IsWatermarkSupported查询能力 2.SetWatermark设置硬件水印 或 AddWatermark添加软件水印 3.水印在视频帧处理链路中叠加 |
| 状态流转 | 无水印 → 有水印（SetWatermark/AddWatermark后）|
| 异常处理路径 | 水印数量超限返回错误；水印数据过大返回错误；位置越界返回错误 |
 
## 规格与约束
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | 最多5个水印（MAX_WATERMARK_NUMBER）；单水印数据不超过80MB（MAX_WATERMARK_SIZE） |
| 业务规则 | 硬件水印和软件水印可融合使用；水印位置基于视频帧像素偏移 |
| 安全与隐私约束 | 水印数据由应用传入，框架不校验水印内容 |
| 性能约束 | 软件水印使用GPU渲染，对编码性能有一定影响 |
 
## 知识关联
 
| 子维度 | 内容 |
| --- | -- |
| 上层依赖 | OpenGL ES（软件水印渲染）、SurfaceEncoderAdapter（硬件水印） |
| 下游影响 | WaterMarkFilter、SurfaceEncoderFilter |
| 平级关联 | VideoResizeFilter（视频缩放，水印前可能需要调整帧大小） |
| 概念对比 | 硬件水印vs软件水印：硬件水印由编码器在编码时叠加，性能更好；软件水印由OpenGL在编码前渲染叠加，更灵活 |
 
## 数据模型
 
| 子维度 | 内容 |
| --- | -- |
| 核心数据结构 | WatermarkConfig（NAPI层位置配置：top/left偏移）、WatermarkConfiguration（NAPI层扩展配置含宽高）、AVBuffer（水印像素数据） |
| 数据流转路径 | PixelMap → AVBuffer → HiRecorderImpl → WaterMarkFilter/SurfaceEncoderFilter |
 
## 代码与符号
 
| 子维度 | 内容 |
| --- | -- |
| 核心API/类 | WaterMarkFilter、AVRecorderNapi::SetWatermark/AddWatermark |
| 核心符号映射 | IsWatermarkSupported → HiRecorderImpl::IsWatermarkSupported; SetWatermark → HiRecorderImpl::SetWatermark; AddWatermark → HiRecorderImpl::AddWatermark |
| 关键配置文件 | 无独立配置，由Pipeline动态构建 |
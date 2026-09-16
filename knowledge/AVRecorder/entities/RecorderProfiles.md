# RecorderProfiles
 
> 录制编码能力查询
 
## 实体概念
 
| 子维度 | 内容 |
| --- | -- |
| 实体名称 | RecorderProfiles（录制Profile / 编码能力查询） |
| 实体定义 | 录制框架提供的编码能力查询机制，应用可查询设备支持的音视频编码格式、分辨率、帧率等参数 |
| 核心特征 | 静态查询接口，无需创建AVRecorder实例即可调用；支持按质量等级查询推荐配置 |
| 类型/分类 | 音频编码能力查询、视频编码能力查询、AVRecorderProfile查询（按质量等级） |
 
## 上下文与场景
 
| 子维度 | 内容 |
| --- | -- |
| 使用场景 | 应用在录制前查询设备支持的编码能力，选择合适的编码参数 |
| 角色与参与方 | 应用（查询方）、CodecCapabilityAdapter（能力提供方） |
| 生命周期 | 无状态，静态查询 |
| 交互流程 | 1.应用调用getAVRecorderProfile(sourceId, qualityLevel) 2.NAPI层通过RecorderServer查询Engine 3.Engine通过CodecCapabilityAdapter查询Codec能力 4.返回AVRecorderProfile |
| 异常处理路径 | 不支持的源或质量等级返回错误 |
 
## 规格与约束
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | 查询结果取决于设备硬件编码器能力 |
| 业务规则 | 质量等级从低到高，返回对应推荐的编码参数 |
 
## 知识关联
 
| 子维度 | 内容 |
| --- | -- |
| 上层依赖 | CodecCapabilityAdapter |
| 下游影响 | 辅助应用选择合适的AVRecorderConfig |
| 平级关联 | AVRecorderConfig（查询结果用于构造Config） |
| 概念对比 | GetAvailableEncoder vs GetAVRecorderProfile：前者返回编码器详细能力数据，后者返回推荐的Profile配置 |
 
## 代码与符号
 
| 子维度 | 内容 |
| --- | -- |
| 核心API/类 | AVRecorderNapi::GetAVRecorderProfile、HiRecorderImpl::GetAvailableEncoder |
| 核心符号映射 | getAVRecorderProfile → JsGetAVRecorderProfile; getAvailableEncoder → JsGetAvailableEncoder |
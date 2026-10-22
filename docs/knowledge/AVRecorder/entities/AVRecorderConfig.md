# AVRecorderConfig
 
> 录制配置数据结构
 
## 实体概念
 
| 子维度 | 内容 |
| --- | -- |
| 实体名称 | AVRecorderConfig（录制配置） |
| 实体定义 | 描述一次录制任务的完整配置信息，包含音视频源类型、编码参数、输出目标等 |
| 核心特征 | 结构化配置对象、支持纯音频/纯视频/音视频/元数据多种组合 |
| 类型/分类 | 按源类型分：纯音频配置（仅audioSourceType+audioProfile）、纯视频配置（仅videoSourceType+videoProfile）、音视频配置、音视频+元数据配置 |
 
## 上下文与场景
 
| 子维度 | 内容 |
| --- | -- |
| 使用场景 | 应用调用AVRecorder.prepare(config)时传入录制配置 |
| 角色与参与方 | 应用（构造配置）、AVRecorderNapi（解析JS对象）、RecorderServer（存储和分发） |
| 生命周期 | prepare时解析生效 → reset时清除 → 可重新配置 |
| 交互流程 | 1.应用构造JS Config对象 2.NAPI层解析为C++ AVRecorderConfig 3.传递到Server和Engine 4.Engine按配置构建Pipeline |
| 异常处理路径 | 配置不合法（如源类型无效、编码格式不支持）返回MSERR_INVALID_VAL |
 
## 规格与约束
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | url必须是有效的fd路径；音频源和视频源各最多1个 |
| 业务规则 | withVideo/withAudio标志需与sourceType一致；fileGenerationMode决定文件创建方式 |
| 性能约束 | 无 |
 
## 知识关联
 
| 子维度 | 内容 |
| --- | -- |
| 上层依赖 | 无 |
| 下游影响 | 决定Pipeline拓扑和Filter组合 |
| 平级关联 | AVRecorderProfile（编码参数子结构） |
| 概念对比 | AVRecorderConfig vs AVRecorderProfile：Config包含完整配置含源和输出，Profile仅含编码参数 |
 
## 数据模型
 
| 子维度 | 内容 |
| --- | -- |
| 核心数据结构 | AVRecorderConfig { audioSourceType, videoSourceType, metaSourceTypeVec, profile, url, rotation, maxDuration, location, metadata, fileGenerationMode, withVideo, withAudio, withLocation } |
| 字段定义 | audioSourceType: AudioSourceType枚举; videoSourceType: VideoSourceType枚举; profile: AVRecorderProfile; url: string(fd路径); rotation: int32(0/90/180/270); maxDuration: int32(秒); fileGenerationMode: APP_CREATE/AUTO_CREATE |
| 数据存储方式 | 非持久化，仅运行时存在 |
| 数据流转路径 | JS → NAPI AVRecorderConfig → Server ConfigInfo → Engine Meta/Filter参数 |
 
## 代码与符号
 
| 子维度 | 内容 |
| --- | -- |
| 核心API/类 | AVRecorderNapi::GetConfig |
| 核心符号映射 | prepare → JsPrepare → GetConfig解析 → Configure |
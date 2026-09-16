# SourceId
 
> 录制源的唯一标识
 
## 实体概念
 
| 子维度 | 内容 |
| --- | -- |
| 实体名称 | SourceId（录制源标识） |
| 实体定义 | 由SetVideoSource/SetAudioSource/SetMetaSource返回的整数ID，用于标识和配置特定的录制源 |
| 核心特征 | 掩码编码区分源类型：0x100系列视频、0x200系列音频、0x300系列元数据；低8位为索引 |
| 类型/分类 | 视频源ID（0x100-0x1FF）、音频源ID（0x200-0x2FF）、元数据源ID（0x300-0x3FF）、DUMMY_SOURCE_ID（0，全局参数） |
 
## 上下文与场景
 
| 子维度 | 内容 |
| --- | -- |
| 使用场景 | Configure/SetParameter时指定配置目标源；GetSurface/GetMetaSurface时获取对应源的Surface |
| 角色与参与方 | HiRecorderImpl（生成和使用SourceId） |
| 生命周期 | SetSource时生成 → Configure时使用 → Reset时失效 |
| 交互流程 | 1.调用SetVideoSource返回videoSourceId_ 2.用该ID调用SetVideoEncoder/SetVideoSize等 3.用该ID调用GetSurface |
| 异常处理路径 | 无效SourceId返回MSERR_INVALID_OPERATION |
 
## 规格与约束
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | 最多1个视频源、1个音频源（VIDEO_SOURCE_MAX_COUNT/AUDIO_SOURCE_MAX_COUNT=1） |
| 业务规则 | SourceId类型校验：IsAudio/IsVideo/IsMeta通过掩码判断 |
 
## 知识关联
 
| 子维度 | 内容 |
| --- | -- |
| 上层依赖 | 无 |
| 下游影响 | Filter路由和配置分发依赖SourceId类型 |
| 平级关联 | DUMMY_SOURCE_ID用于全局参数配置 |
| 概念对比 | SourceId vs sourceId_：前者是通用概念，后者是HiRecorderImpl内部成员 |
 
## 代码与符号
 
| 子维度 | 内容 |
| --- | -- |
| 核心API/类 | SourceIdGenerator |
| 核心符号映射 | GenerateAudioSourceId → SourceIdGenerator::GenerateAudioSourceId; IsVideo → SourceIdGenerator::IsVideo |
| 核心代码片段 | AUDIO_MASK=0x200, VIDEO_MASK=0x100, META_MASK=0x300, INDEX_MASK=0xFF |
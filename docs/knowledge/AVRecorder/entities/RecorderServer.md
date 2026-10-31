# RecorderServer
 
> 录制服务端实现，运行在media_service进程中
 
## 实体概念
 
| 子维度 | 内容 |
| --- | -- |
| 实体名称 | RecorderServer（录制服务端） |
| 实体定义 | IRecorderService接口的服务端实现，运行在media_service进程，管理录制配置、状态、回调和DFX |
| 核心特征 | 持有IRecorderEngine实例、维护RecStatus状态机、TaskQueue串行化操作、WatchDog超时保护 |
| 类型/分类 | 服务端组件 |
 
## 上下文与场景
 
| 子维度 | 内容 |
| --- | -- |
| 使用场景 | 所有录制操作的跨进程服务端处理 |
| 角色与参与方 | RecorderClient（IPC调用方）、HiRecorderImpl（引擎执行方）、RecorderCallback（上层回调） |
| 生命周期 | Create()创建 → 配置阶段 → Prepare → Start → Pause/Resume → Stop → Reset/Release |
| 交互流程 | 1.Client通过IPC调用Server方法 2.Server校验状态后转发到Engine 3.Engine通过IRecorderEngineObs回调 4.Server通过RecorderCallback回调Client |
| 状态流转 | REC_INITIALIZED → REC_CONFIGURED → REC_PREPARED → REC_RECORDING ↔ REC_PAUSED；可转入REC_ERROR |
| 异常处理路径 | Engine上报错误→OnError→回调Client；系统关机→SaveDocumentSyncCallback→紧急Stop |
 
## 规格与约束
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | 运行在media_service进程，需通过IPC与客户端通信 |
| 业务规则 | TaskQueue保证操作串行化；WatchDog监控录制时长；统计事件上报 |
| 安全与隐私约束 | IPC层需Token校验 |
| 性能约束 | 避免在Server层做耗时操作，转发到Engine层执行 |
 
## 知识关联
 
| 子维度 | 内容 |
| --- | -- |
| 上层依赖 | IRecorderService接口、IPC框架、TaskQueue |
| 下游影响 | HiRecorderImpl（IRecorderEngine） |
| 平级关联 | MediaLibraryAdapter、其他媒体服务（PlayerServer等） |
| 概念对比 | RecorderServer vs RecorderClient：Server是服务端实现，Client是IPC代理 |
 
## 数据模型
 
| 子维度 | 内容 |
| --- | -- |
| 核心数据结构 | ConfigInfo（内部配置结构体）、StatisticalEventInfo（DFX统计） |
| 字段定义 | ConfigInfo包含videoSource/audioSource/videoCodec/audioCodec/width/height/frameRate/bitRate/isHdr/enableTemporalScale/enableStableQualityMode/enableBFrame/maxDuration/format/maxFileSize/rotation/url/fileGenerationMode等 |
| 数据流转路径 | Client IPC参数 → Server ConfigInfo → Engine Configure |
 
## 代码与符号
 
| 子维度 | 内容 |
| --- | -- |
| 核心API/类 | RecorderServer |
| 核心符号映射 | Create → RecorderServer::Create; Prepare → RecorderServer::Prepare; Start → RecorderServer::Start |
| 关键配置文件 | services/services/recorder/BUILD.gn |
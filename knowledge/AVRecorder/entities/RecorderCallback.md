# RecorderCallback
 
> 录制回调机制
 
## 实体概念
 
| 子维度 | 内容 |
| --- | -- |
| 实体名称 | RecorderCallback（录制回调） / IRecorderEngineObs（引擎观察者） |
| 实体定义 | 录制框架的事件回调机制，从Engine层向上层报告错误、信息和音频采集变更事件 |
| 核心特征 | 双层回调：IRecorderEngineObs（Engine→Server）+ RecorderCallback（Server→NAPI→应用） |
| 类型/分类 | 错误回调（OnError）、信息回调（OnInfo）、音频采集变更回调（OnAudioCaptureChange） |
 
## 上下文与场景
 
| 子维度 | 内容 |
| --- | -- |
| 使用场景 | 录制过程中上报错误、达到最大时长/文件大小通知、音频采集参数变更通知 |
| 角色与参与方 | HiRecorderImpl（事件源）、RecorderServer（中间转发）、AVRecorderNapi（JS回调分发） |
| 生命周期 | SetRecorderCallback注册 → 录制期间持续有效 → Release时清除 |
| 交互流程 | 1.Engine检测到事件 2.通过IRecorderEngineObs::OnInfo/OnError通知Server 3.Server通过RecorderCallback通知NAPI 4.NAPI通过napi_threadsafe_function调用JS回调 |
| 异常处理路径 | 回调异常不影响录制主流程 |
 
## 规格与约束
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | 回调在非JS线程触发，需通过napi_threadsafe_function调度到JS线程 |
| 业务规则 | ErrorType包含CREATE_FILE_FAIL/WRITE_FILE_FAIL/INTERNAL；InfoType包含MAX_DURATION_APPROACHING/REACHED等 |
 
## 知识关联
 
| 子维度 | 内容 |
| --- | -- |
| 上层依赖 | NAPI线程安全函数机制 |
| 下游影响 | 无 |
| 平级关联 | AVRecorderEvent（NAPI层事件类型：stateChange/error/audioCapturerChange/photoAssetAvailable） |
| 概念对比 | OnError vs OnInfo：Error表示录制失败需处理，Info表示运行时信息通知 |
 
## 代码与符号
 
| 子维度 | 内容 |
| --- | -- |
| 核心API/类 | IRecorderEngineObs、RecorderCallback |
| 核心符号映射 | OnError → IRecorderEngineObs::OnError; OnInfo → IRecorderEngineObs::OnInfo; OnAudioCaptureChange → IRecorderEngineObs::OnAudioCaptureChange |
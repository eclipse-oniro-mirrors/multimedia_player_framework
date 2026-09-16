# AVRecorder
 
> 录制框架对应用暴露的JS/ArkTS API对象
 
## 实体概念
 
| 子维度 | 内容 |
| --- | -- |
| 实体名称 | AVRecorder（音视频录制器） |
| 实体定义 | 录制框架面向JS/ArkTS应用的唯一入口对象，提供音视频录制全生命周期管理 |
| 核心特征 | 异步Promise/Callback双模式、7状态有限状态机、事件回调机制、支持水印和元数据 |
| 类型/分类 | 按场景分：纯音频录制、纯视频录制、音视频同步录制、录屏+元数据录制 |
 
## 上下文与场景
 
| 子维度 | 内容 |
| --- | -- |
| 使用场景 | 相机录像、语音备忘录、屏幕录制、通话录音、带水印的合规录制 |
| 角色与参与方 | 上层应用（调用者）、RecorderClient（IPC转发）、RecorderServer（服务端处理） |
| 生命周期 | createAVRecorder()创建 → prepare() → start() → [pause()/resume()] → stop() → release() |
| 交互流程 | 1.应用调用createAVRecorder创建实例 2.配置AVRecorderConfig后调用prepare 3.视频场景调用getInputSurface获取Surface给Camera 4.调用start开始录制 5.录制完成后stop 6.调用release释放资源 |
| 状态流转 | idle → prepared → started ↔ paused → stopped → released；任意状态可转入error |
| 异常处理路径 | error状态下仅允许reset（回到idle重新配置）或release（释放资源） |
 
## 规格与约束
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | 必须在主线程创建，异步操作在TaskQueue中执行 |
| 业务规则 | 状态机严格管控操作合法性；Prepare前必须完成Source和Config设置 |
| 安全与隐私约束 | 音频录制需ohos.permission.MICROPHONE；视频录制需ohos.permission.CAMERA |
| 性能约束 | 异步操作避免阻塞JS主线程；回调通过napi_threadsafe_function传递 |
 
## 知识关联
 
| 子维度 | 内容 |
| --- | -- |
| 上层依赖 | NAPI框架、TaskQueue |
| 下游影响 | RecorderClient → RecorderServer → HiRecorderImpl |
| 平级关联 | AVPlayer（播放框架）、AVCodec（编解码） |
| 概念对比 | AVRecorder vs MediaRecorder：AVRecorder是新版API，支持更丰富的配置（水印/元数据/Profile查询） |
 
## 数据模型
 
| 子维度 | 内容 |
| --- | -- |
| 核心数据结构 | AVRecorderConfig（配置）、AVRecorderProfile（编码参数）、WatermarkConfig（水印位置） |
| 字段定义 | audioSourceType: AudioSourceType; videoSourceType: VideoSourceType; profile: AVRecorderProfile; url: string; rotation: int32; maxDuration: int32; location: Location; fileGenerationMode: FileGenerationMode |
| 数据流转路径 | JS Config → NAPI解析 → RecorderClient IPC → RecorderServer → Engine Configure |
 
## 代码与符号
 
| 子维度 | 内容 |
| --- | -- |
| 核心API/类 | AVRecorderNapi |
| 核心符号映射 | createAVRecorder → JsCreateAVRecorder; prepare → JsPrepare; start → JsStart; stop → JsStop; release → JsRelease |
| 关键配置文件 | frameworks/js/avrecorder/BUILD.gn |
| 核心代码片段 | 状态校验：CheckStateMachine(opt)检查stateCtrlMap[opt]是否包含当前状态 |
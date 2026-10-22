# 关键流程

> 播放器初始化、Pipeline 搭建、Source/Demuxer 初始化、内存回收恢复等核心流程。

## 一、播放器初始化与播放流程

```
1. 创建播放器
   Client 调用 PlayerClient::Create(ipcProxy)
   → 创建 PlayerListenerObject 并通过 IPC 设置到服务端

2. 设置源
   Client::SetSource(url) → Proxy → IPC → Stub → PlayerServer
   → InitPlayEngine 初始化引擎 + SetSource
   → 状态 → INITIALIZED

3. 异步准备
   Client::PrepareAsync() → Server HandlePrepare (TaskMgr 异步)
   → 引擎 PrepareAsync → 状态 → PREPARING

4. 准备完成回调
   引擎 OnInfo(PLAYER_PREPARED) → Server 状态 → PREPARED
   → ListenerProxy IPC 通知客户端

5. 开始播放
   Client::Play() → Server HandlePlay (TaskMgr 异步)
   → 引擎 Play → 状态 → STARTED
```

## 二、Pipeline 搭建流程（10 步）

```
1. PlayerServer → HiPlayerImpl::CreatePlayerEngine() → 创建 Pipeline
2. PlayerServer → SetSource() 记录播放源
3. PlayerServer → Prepare() → HiPlayerImpl 创建 DemuxerFilter + SetDataSource
4. HiPlayerImpl → Pipeline::AddHeadFilters(DemuxerFilter)
5. Pipeline::Prepare() → DemuxerFilter::Prepare() 按轨道创建下游链路
6. DemuxerFilter OnCallback(音频轨道) → HiPlayerImpl::LinkAudioDecoderFilter
7. DemuxerFilter OnCallback(视频轨道) → HiPlayerImpl::LinkVideoDecoderFilter
8. AudioDecoderFilter::Prepare() → 创建 AudioSinkFilter 并链接
9. AudioSinkFilter::Prepare() → 设置 OutputBufferQueue 给解码器
10. DecoderSurfaceFilter::Prepare() → 设置 OutputBufferQueue 给 Demuxer
```

### Pipeline 搭建异常分支

```
[步骤3 异常] SetSource 路径校验失败
  → PlayerServer::SetSource 校验 URL/fd 合法性
  → 路径穿越或 fd 无效 → 返回 MSERR_INVALID_VAL
  → 不进入 INITIALIZED 状态，状态保持 IDLE

[步骤5 异常] DemuxerFilter::Prepare() 失败
  → SniffMediaType() 所有插件 confidence=0 → GuessMediaType 按 URI 后缀猜测
  → GuessMediaType 也无法识别 → OnCallback(ERROR_CODE) → HiPlayerImpl 上报 MSERR_UNSUPPORT_FORMAT
  → Pipeline 发送 EVENT_ERROR → PlayerServer 状态回退到 INITIALIZED → 通知客户端 OnError

[步骤6/7 异常] Decoder Filter 创建/链接失败
  → LinkAudioDecoderFilter：无匹配音频解码器插件 → 记录错误但允许纯视频播放
  → LinkVideoDecoderFilter：无匹配视频解码器插件 → 记录错误但允许纯音频播放
  → 音视频解码器均不可用 → Pipeline 发送 EVENT_ERROR(MSERR_UNSUPPORT_FORMAT)

[步骤8/9 异常] AudioSinkFilter 初始化失败
  → AudioRenderer 创建失败（无音频设备/权限不足）
  → Pipeline 发送 EVENT_ERROR → PlayerServer 上报 OnError
  → 播放器状态回退到 INITIALIZED

[步骤10 异常] Surface 未设置或已释放
  → DecoderSurfaceFilter::Prepare() 检测 surface_ 为空
  → 视频解码器无法配置输出 → 视频轨道跳过，仅音频播放
  → Surface 中途释放 → OnSurfaceReleased 回调 → 停止视频解码
```

## 三、Source 与 Demuxer 初始化流程（14 步）

```
1.  PluginManager::RegisterPlugins() → 注册插件 → g_pluginInputFormat 映射
2.  AVDemuxer 创建 MediaDemuxer → 创建 DataPacker 和 Source
3.  SetBufferQueue() → DemuxerPlugin 的 bufferQueueVector_
4.  SetDataSource() → Source::SetSource 选择插件 → 创建 SourcePlugin
5.  Source::GetSeekable() → 缓存 seekMode_
6.  Source::Start() → Push 模式启动 ReadLoop
7.  MediaDemuxer::SetDataSource() → Prepare() → DataPacker.Start()
8.  初始化 checkRange_/peekRange_/getRange_ 回调
9.  InitTypeFinder() → TypeFinder::FindMediaType()
10. SniffMediaType() → 循环嗅探比较 confidence
11. Sniff 失败 → GuessMediaType() 按 URI 后缀猜测
12. InitPlugin() → PluginManager 创建 DemuxerPlugin
13. DemuxerPlugin::InitAVFormatContext + AllocAVIOContext
14. ReadSample() → MediaDemuxer::Start() → av_read_frame() → 分发到 BufferQueue
```

## 四、异步准备流程

```
1. PrepareAsync()
2. DoSetSource() → 创建 DemuxerFilter + 设置数据源
3. DoInitDemuxer() → 添加到 Pipeline 头 + Init
4. pipeline_->Prepare()
5. Pipeline 依次调用各 Filter 的 Init/Configure
6. Demuxer 解析媒体信息 → OnCallback(NEXT_FILTER_NEEDED)
7. HiPlayerImpl 根据流类型 LinkAudio/VideoDecoderFilter
8. 所有 Filter 就绪 → Pipeline 发送 EVENT_READY
9. HiPlayerImpl 回调 INFO_TYPE_STATE_CHANGE(PLAYER_PREPARED)
```

### 异步准备异常分支

```
[步骤2 异常] DoSetSource 失败
  → 源文件不存在/网络不可达 → SourcePlugin::Read 返回错误
  → DataPacker 无数据 → DemuxerFilter OnCallback(ERROR)
  → Pipeline 发送 EVENT_ERROR → HiPlayerImpl 上报 MSERR_OPEN_FILE_FAILED / MSERR_NETWORK_ERROR
  → PlayerServer 状态从 PREPARING 回退到 INITIALIZED → 通知客户端 OnError

[步骤3 异常] DoInitDemuxer 失败
  → MediaDemuxer::Init 已执行 → 再次 Init 返回 MSERR_INVALID_OPERATION
  → DemuxerPlugin 创建失败（ffmpeg avformat_open_input 返回非0）
  → Pipeline 发送 EVENT_ERROR(MSERR_UNSUPPORT_FORMAT) → 上报客户端

[步骤4 异常] Pipeline::Prepare 超时
  → XCollie 定时器触发 → 上报 MSERR_TIMEOUT
  → Pipeline 发送 EVENT_ERROR → 状态回退
  → 注意：超时后需调用 Pipeline::Stop 释放已创建的 Filter 资源

[步骤7 异常] Decoder Filter 链接失败
  → 无可用解码器 → Pipeline 仅保留可用的轨道
  → 所有轨道均不可用 → 上报 MSERR_UNSUPPORT_FORMAT

[步骤8 异常] EVENT_READY 未收到
  → Pipeline 内部 Filter 初始化卡住 → XCollie 超时检测
  → 部分 Filter 报错但 Pipeline 未聚合上报 → DfxAgent 打点记录
  → 恢复策略：调用 Stop → 释放资源 → 回退到 INITIALIZED
```

## 五、编解码器初始化/去初始化流程

```
1. HiPlayerImpl 收到 NEXT_FILTER_NEEDED 回调
2. 根据流类型选择 LinkAudio/Video/SubtitleSinkFilter
3. 创建对应 Decoder Filter 实例
4. 添加到 Pipeline
5. Filter::Init() 初始化编解码器插件
6. 配置 Filter 参数（Surface / PCM 回调）
7. 链接上下游 Filter AVBufferQueue
```

## 六、Seek 去重合并流程

```
1. 用户调用 Seek(mSeconds, mode)
2. SeekForInt64() 获取 recMutex_ 递归锁
3. SEEK_CONTINOUS → 直接调用 playerService_->Seek() 并返回
4. 更新 mCurrentPosition / mCurrentSeekMode
5. 评估条件：(mSeekPosition != mCurrentPosition || mSeekMode != mCurrentSeekMode) && !isSeeking_
6. 条件满足 → isSeeking_ = true, 更新 mSeekPosition/mSeekMode, 调用 Seek()
7. Seek 失败 → ResetSeekVariables()
8. INFO_TYPE_SEEKDONE → HandleSeekDoneInfo()
9. 有待处理请求 → 立即执行新 Seek；否则 ResetSeekVariables()
```

### Seek 异常分支

```
[步骤1 异常] Seek 在非法状态下调用
  → PlayerServer 状态机校验：非 PREPARED/PLAYING/PAUSED/COMPLETED 状态
  → 返回 MSERR_INVALID_STATE，不进入 Seek 流程

[步骤6 异常] Pipeline::Seek 失败
  → Pipeline::SendMessage(SEEK) 返回错误 → HiPlayerImpl 上报 OnError
  → SeekAgent 处理失败 → ResetSeekVariables() 重置 isSeeking_=false
  → 注意：Seek 失败后播放位置可能已偏离，需通过 GetPosition 获取实际位置

[步骤7 异常] Seek 执行过程中 Demuxer 错误
  → av_seek_frame 返回负值 → ffmpeg 无法定位到目标时间戳
  → DemuxerFilter 上报错误 → Pipeline 传播 EVENT_ERROR
  → 恢复策略：保持当前播放位置继续播放，不上报 SEEKDONE

[步骤8 异常] SEEKDONE 回调与预期位置不符
  → Seek 实际落点与请求位置偏差过大（关键帧对齐导致）
  → HiPlayerImpl 收到 SEEKDONE 后检查实际位置
  → 偏差在可接受范围 → 正常上报；偏差超限 → 记录 DfxAgent 打点

[并发异常] 连续快速 Seek 导致竞态
  → TwoPhaseTaskItem 机制：新 Seek 在 Prepare 阶段替换旧任务的参数
  → 旧 Seek 的 Execute 被跳过，仅执行最新目标位置
  → 极端情况：替换发生在旧 Seek Execute 之后 → SEEKDONE 位置为旧值
  → 恢复：下一个 SEEKDONE 事件会携带最新位置
```

## 七、内存回收恢复流程

### 回收流程

```
系统内存压力 / 应用后台
  → PlayerMemManage::HandleOnTrim / RecordAppState
  → FindBackGroundPlayerFromVec
  → Local 资源：LocalResourceRelease（保存 RecoverConfigInfo + Reset）
  → Network 资源：NetworkResourceRelease（HandleCodecBuffers 释放 Buffer）
```

### 恢复流程

```
应用前台 / 用户操作
  → PlayerMemManage::RecoverByMemManage
  → Local 资源：LocalResourceRecover（重初始化引擎 + 设源 + 配置 + Seek）
  → Network 资源：NetworkRecover（恢复 Buffer + Seek）
```

### 内存回收恢复异常分支

```
[回收异常] RecoverConfigInfo 不完整
  → 缺少 URL/位置/Surface 等关键字段 → RecoverByMemManage 无法完整恢复
  → 降级策略：仅恢复可恢复的部分，缺失字段记录 DfxAgent 打点
  → 严重缺失 → 上报 OnError(MSERR_UNKNOWN)，通知客户端重建播放器

[恢复异常] LocalResourceRecover 引擎重初始化失败
  → EngineFactoryRepo::CreatePlayerEngine 返回空 → 新引擎创建失败
  → 重试策略：最多重试1次，间隔 100ms
  → 仍失败 → 上报 OnError(MSERR_SERVICE_DIED)，客户端需重新 CreatePlayer

[恢复异常] RecoverByMemManage Seek 回原位失败
  → 恢复后 Seek 到回收前位置失败 → 从头开始播放
  → 记录 DfxAgent 打点（恢复位置偏差）
  → 不上报错误，正常播放即可

[恢复异常] Surface 已在回收期间被客户端释放
  → RecoverConfigInfo 中保存了 Surface token 但客户端已释放
  → DecoderSurfaceFilter 检测 Surface 无效 → 跳过视频轨道恢复
  → 仅恢复音频播放，不上报错误
```

## 八、服务实例创建流程

```
1. Client → MediaServiceFactory::GetInstance()
2. CreatePlayerService() → IPC 创建请求
3. MediaServer 接收 → 创建 PlayerServer 实例
4. MediaServerManager 注册实例
5. 返回服务 Proxy 给客户端
```

## 九、播放器任务队列流程

```
1. PlayerServer → taskMgr_.LaunchTask(task, type, name, cancelTask)
2. STATE_CHANGE → 直接入队
3. SEEKING/RATE_CHANGE → 检查同类型待处理任务 → 替换旧的
4. EnqueueTask → taskThread_ 异步执行
5. 执行 HandlePrepare/HandlePlay/HandleSeek 等业务逻辑
6. MarkTaskDone → 标记完成
7. pendingTwoPhaseTasks_ → 取下一个执行
```

## 十、JS-NAPI 桥接流程

```
1. JS 层调用 NAPI 方法（如 JsPrepare）
2. NAPI 层检查状态机有效性
3. 封装为 TaskHandler → TaskQueue 异步排队
4. Worker 线程执行 → PlayerImpl::Prepare()
5. PlayerImpl → IPC → Server 执行
6. 回调 → napi_send_event 到 JS 主线程
7. JS 触发 stateChange 事件
```

## 十一、账户切换处理流程

```
1. 系统账号切换事件触发
2. AccountListener 接收通知
3. AccountObserver 分发给所有注册的回调
4. 各媒体服务（PlayerServer/RecorderServer）接收通知
5. 执行账户切换处理（暂停播放/释放资源）
6. 新账户登录后客户端可重新创建实例
```

## 十二、直播流控制流程

```
1. StartFlvCheckLiveDelayTime → 启动延迟检测
2. LiveController 创建定时任务 DoCheckLiveDelayTime
3. 检查当前播放位置与直播延迟关系
4. 延迟过大 → 自动调速追赶
5. 网络中断 → DoRestartLiveLink 重连
6. OnInfo 回调通知上层直播状态变更
7. StopCheckLiveDelayTime → 停止检测
```

## 十三、播放列表切换流程

```
1. 验证目标迭代器 nextIndex 有效
2. 保存当前状态 (prevIndex, prevIsFirstSelect)
3. 更新 curSrcId_ + isSwitchingItem_ 标志
4. ON_SCOPE_EXIT 设置异常恢复逻辑
5. Reset() → 清除当前媒体源
6. SetMediaSource() → 设置新媒体源
7. Prepare() → 准备新源
8. Play() → 开始播放
9. 成功 → CANCEL_SCOPE_EXIT_GUARD 取消恢复逻辑
```

## 十四、框架核心交互流程

```
Application (JS/ArkTS/CangJie/Native C)
  → Bridge Layer (NAPI/FFI/C API)
  → Native API
  → IPC (Binder) → Service Server
  → EngineFactory 创建/获取引擎
  → Engine 加载动态库 (dlopen)
  → HDI 硬件驱动
```

## 知识关联

- [[architecture]] - 架构总览
- [[engine-layer-entities]] - 引擎层实体
- [[service-layer]] - 服务层实体

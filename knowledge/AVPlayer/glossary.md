# 术语表

> 只说明模型不知道的术语，常识类不要写

## 引擎工厂仓库（EngineFactoryRepo）
通过 dlopen 动态加载引擎工厂 .so 并按 Score() 打分选择最优引擎。场景类型 PLAYER/RECORDER/TRANSCODER/LPP_STREAMER 决定打分结果。详见 [[engine-factory-and-selection]]

**触发加载**：当任务涉及"引擎选择/引擎注册/新增引擎/dlopen加载/打分机制"时 → 必读 [[engine-factory-and-selection]]

## 插件嗅探（Sniff）
Source/Demuxer/Codec 插件注册 Sniff 后由 PluginManager 循环调用，返回 confidence 分数用于自动选择最优插件。新增格式只需注册 Sniff 无需修改框架。

**触发加载**：当任务涉及"新增插件/插件注册/格式支持/插件选择/confidence"时 → 必读 [[media-source-and-protocol]] + [[engine-layer-entities]]

## 缓冲队列（AVBufferQueue / BQ）
Filter 间零拷贝数据传递队列，含 Producer/Consumer 双端。容量按轨道类型配置：音频输入 8、音频输出 30、视频 4。满时 Producer 阻塞等待。

**触发加载**：当任务涉及"BufferQueue/数据传递/缓冲区容量/BQ 阻塞/生产消费"时 → 必读 [[pipeline-architecture]] + [[av-sync-and-buffer]]

## 缓冲数据单元（AVBuffer）
Pipeline 基本数据单元，一个 AVBuffer 对应一帧数据，含 data（帧数据）、pts（显示时间戳）、flags（关键帧/EOS 等标志）。

**触发加载**：当任务涉及"帧数据/pts/数据单元/AVBuffer"时 → 必读 [[pipeline-architecture]]

## 契约接口（InnerAPI）
服务层与引擎层的契约接口边界（MediaDemuxer InnerApi / MediaCodec InnerApi / VideoDecoder InnerApi）。Pipeline 层仅依赖 InnerAPI 头文件，屏蔽 .so 插件实现差异。详见 [[engine-layer-entities]]

**触发加载**：当任务涉及"InnerAPI/接口边界/契约头文件/层间解耦"时 → 必读 [[engine-layer-entities]] + [[architecture]]

## 两阶段异步任务（TwoPhaseTaskItem）
支持 Prepare/Execute 分离。Seek 场景中新 Seek 替换旧任务的 Prepare 阶段，仅执行最新目标位置，实现连续 Seek 去重。

**触发加载**：当任务涉及"任务队列/连续Seek/去重/TaskMgr/异步任务"时 → 必读 [[player-lifecycle]] + [[seek-architecture]]

## 内存恢复配置（RecoverConfigInfo）
保存完整播放状态（URL/位置/音量/速度/Surface/轨道信息），确保系统内存回收后可完整恢复到回收前位置。详见 [[service-layer]]

**触发加载**：当任务涉及"内存回收/状态恢复/RecoverConfig/前台后台/内存压力"时 → 必读 [[memory-and-background]] + [[service-layer]]

## 回调冻结/解冻（Freeze/UnFreeze）
IPC 回调冻结机制。应用切后台时 PlayerServiceStub 执行 Freeze，PlayerListenerProxy 设 isFrozen_=true 跳过回调发送，减少后台序列化开销；切前台 UnFreeze 恢复。

**触发加载**：当任务涉及"后台回调/Freeze/冻结/前后台切换/isFrozen"时 → 必读 [[ipc-communication]] + [[memory-and-background]]

## 批量配置（ConfigInfo）
在 PrepareAsync 前一次性设置音量/循环/速度/策略等参数，HandlePrepare 时统一应用，减少 IPC 调用次数。

**触发加载**：当任务涉及"播放配置/批量参数/PrepareAsync/HandlePrepare"时 → 必读 [[player-lifecycle]] + [[service-layer]]

## 数据推拉模式（DataPacker Push/Pull）
Source 与 Demuxer 间的数据缓冲模式。Push 模式：Source ReadLoop 主动推送；Pull 模式：Demuxer 按需拉取。流媒体用 Push，本地文件用 Pull。

**触发加载**：当任务涉及"数据缓冲/Push/Pull/Source数据流/流媒体数据"时 → 必读 [[pipeline-architecture]] + [[media-source-and-protocol]]

## 流水线过滤器链（Pipeline Filter Chain）
Histreamer 数据处理链路：DemuxerFilter → AudioDecoderFilter → AudioSinkFilter / DecoderSurfaceFilter → VideoSink。Filter 通过 BufferQueue 连接，新增 Filter 插入链路无需修改已有 Filter。详见 [[engine-layer-entities]]

**触发加载**：当任务涉及"Pipeline/Filter/数据链路/新增Filter/链路编排"时 → 必读 [[pipeline-architecture]] + [[engine-layer-entities]]

## 播放器状态机（PlayerServerStateMachine）
8 状态有限状态机（Idle→Initialized→Preparing→Prepared→Playing→Paused→Stopped→PlaybackCompleted），每个状态类限制允许的操作，非法操作返回 MSERR_INVALID_STATE。详见 [[service-layer]]

**触发加载**：当任务涉及"状态机/状态转换/非法操作/MSERR_INVALID_STATE"时 → 必读 [[player-lifecycle]] + [[service-layer]] + [[design-patterns]]

## 音视频同步管理器（MediaSyncManager）
以音频播放进度为基准时钟，RenderLoop 按帧率控制视频送显，视频过早则延迟、过晚则丢帧追赶。详见 [[engine-layer-entities]]

**触发加载**：当任务涉及"音视频同步/AV同步/丢帧/基准时钟/RenderLoop"时 → 必读 [[av-sync-and-buffer]] + [[engine-layer-entities]]

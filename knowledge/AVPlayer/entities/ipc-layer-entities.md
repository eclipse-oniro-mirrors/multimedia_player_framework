# IPC 层实体

> PlayerClient、存根/代理、监听器等跨进程通信实体

## 实体概念

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| PlayerClient | 应用进程播放器代理，持有 IPC 代理端和监听器存根 | playerProxy_ (PlayerServiceProxy)；listenerStub_ (PlayerListenerStub)；callback_ (应用层 PlayerCallback)；注册死亡通知监控服务端死亡 | 客户端 |
| PlayerServiceProxy | IPC 调用端，序列化参数发送到服务端 | SetSource 序列化 URL/文件描述符/数据源；PrepareAsync/Play/Pause/Stop 生命周期控制；SeekTo 序列化 Seek 参数；SetVolume/SetSpeed/SetLooping 参数设置；SetSurface 序列化 Surface 序列号 | 客户端代理端 |
| PlayerServiceStub | IPC 服务端入口，接收请求并分发 | playerFuncs_ 方法映射表（消息码 → 处理函数）；Freeze/UnFreeze 冻结/解冻 IPC 回调；SetListenerObject 注册客户端回调代理；权限校验 | 服务端存根 |
| PlayerServiceStubMem | 内存管理扩展存根，继承 PlayerServiceStub | Create() 创建带内存管理的存根；ResetFrontGroundRecall/ResetBackGroundRecall/RecoverByMemManage 回调 | 服务端存根扩展 |
| PlayerListenerCallback | 桥接类，将引擎回调转发到 IPC 通路 | OnInfo/OnError 信息/错误事件桥接；SetFreezeFlag 设置冻结标志；持有 listenerProxy_ (IStandardPlayerListener.代理端) | 回调通路 |
| PlayerListenerProxy | 服务端回调代理端，序列化事件发送到客户端 | isFrozen_ 标志控制是否发送回调 | 回调通路代理端 |
| PlayerListenerStub | 客户端回调接收端，反序列化事件并调用应用层回调 | OnRemoteRequest 接收 PlayerListenerProxy 回调并按类型分发；OnInfo/OnError/OnVideoSizeChanged 等从 MessageParcel 反序列化参数后转发到 PlayerCallback | 回调通路存根 |
| IStandardPlayerService | 客户端→服务端 播放控制接口，约70+ 方法 | SetSource/SetMediaSource 设置源；PrepareAsync/Play/Pause/Stop 生命周期；SeekTo/SeekContinous 定位；SetVolume/SetSpeed/SetLooping 参数设置；SetSurface/SetVideoScaleType 视频设置；SelectTrack/GetCurrentTrack 轨道选择；SetPlaybackStrategy/SetPlayTrackSelectionFilter 播放策略；AddAdsMediaSource/SkipCurrentAdsMediaSource 广告管理 | IPC 接口定义 |
| IStandardPlayerListener | 服务端→客户端 事件通知接口 | OnInfo(类型, 附加信息, 信息体)；OnError(错误类型, 错误码)；SetFreezeFlag(是否冻结)；SetInterruptListenerFlag(是否注册) | IPC 接口定义 |

## 上下文与场景

### 交互流程

**IPC 调用通路（客户端 → 服务端）**：

```
应用调用 → PlayerClient → PlayerServiceProxy (序列化)
  → IPC Binder → PlayerServiceStub (反序列化 + 分发)
  → PlayerServer 处理
```

**IPC 回调通路（服务端 → 客户端）**：

```
引擎事件 → PlayerListenerCallback (桥接)
  → PlayerListenerProxy (序列化 + isFrozen_ 检查)
  → IPC Binder → PlayerListenerStub (反序列化)
  → 应用层 PlayerCallback
```

**冻结/解冻机制**：

```
应用切后台 → PlayerServiceStub::DoFreeze
  → PlayerListenerProxy::isFrozen_ = true
  → 回调不再发送到客户端

应用切前台 → PlayerServiceStub::DoUnFreeze
  → PlayerListenerProxy::isFrozen_ = false
  → 恢复回调发送
```

### 异常处理路径

| 异常场景 | 处理方式 |
|---------|---------|
| 服务端死亡 | PlayerClient 通过死亡通知监控，上报错误到应用层 |
| 客户端死亡 | PlayerServiceStub 通过死亡通知清理死亡客户端资源 |
| IPC 回调冻结 | PlayerListenerProxy::isFrozen_ 为 true 时跳过回调发送，减少后台开销 |

### 角色与参与方

| 角色 | 职责 |
|------|------|
| PlayerClient | 应用进程代理，转发调用 + 接收回调 |
| PlayerServiceProxy | 序列化参数，发起 IPC 调用 |
| PlayerServiceStub | 反序列化请求，分发到 PlayerServer |
| PlayerListenerProxy | 序列化事件，发起 IPC 回调 |
| PlayerListenerStub | 反序列化事件，调用应用回调 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 系统限制 | IPC 传输数据必须通过 MessageParcel 序列化，不可共享裸指针 |
| 业务规则 | Surface 通过序列号传递，不直接跨进程共享 Surface 对象 |
| 业务规则 | 冻结期间回调被抑制，解冻后补发关键状态变更 |
| 安全与隐私约束 | PlayerServiceStub 检查调用方权限 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上层依赖 | [[api-layer]] — PlayerImpl 持有 PlayerClient 发起 IPC |
| 下游影响 | [[service-layer]] — PlayerServiceStub 分发请求到 PlayerServer |
| 平级关联 | PlayerServiceProxy ↔ PlayerListenerProxy — 前者负责调用通路，后者负责回调通路 |
| 概念对比 | IStandardPlayerService (调用接口) vs IStandardPlayerListener (回调接口) — 双向 IPC 的两个方向 |

## 数据模型

### ConfigInfo

PlayerServer 的配置结构体，在 PrepareAsync 前设置，HandlePrepare 时一次性应用：

| 字段 | 说明 |
|------|------|
| looping | 是否循环 |
| leftVolume / rightVolume | 左右音量 |
| speedMode / speedRate | 速度模式与倍率 |
| url | 播放地址 |
| effectMode | 音效模式 |
| header | HTTP 头 |
| strategy_ | 播放策略 |
| trackSelectionFilter_ | 轨道选择过滤 |

### PlayerStates 枚举

| 值 | 说明 |
|----|------|
| PLAYER_STATE_ERROR | 错误 |
| PLAYER_IDLE | 初始 |
| PLAYER_INITIALIZED | 已初始化 |
| PLAYER_PREPARING | 准备中 |
| PLAYER_PREPARED | 准备完成 |
| PLAYER_STARTED | 播放中 |
| PLAYER_PAUSED | 暂停 |
| PLAYER_STOPPED | 停止 |
| PLAYER_PLAYBACK_COMPLETE | 播放完成 |

### PlayerServerTaskType 枚举

| 值 | 说明 |
|----|------|
| STATE_CHANGE | 状态变更 |
| SEEKING | Seek 操作 |
| RATE_CHANGE | 倍速变更 |
| CANCEL_TASK | 取消任务 |
| SEEK_CONTINOUS | 连续 Seek |
| LIGHT_TASK | 轻量任务 |
| FREEZE_TASK | 冻结任务 |
| UNFREEZE_TASK | 解冻任务 |

### TwoPhaseTaskItem

两阶段任务结构体，支持 Seek 等需要准备的异步操作：

| 字段 | 说明 |
|------|------|
| type | PlayerServerTaskType |
| task | 执行函数 |
| cancelTask | 取消函数 |
| taskName | 任务名称 |
| seekMode_ / seekTime_ | Seek 参数 |
| speedMode_ | 倍速参数 |

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| PlayerClient | `services/services/player/ipc/client/` | PlayerClient |
| PlayerServiceProxy | `services/services/player/ipc/proxy/` | PlayerServiceProxy::SetSource/PrepareAsync/Play |
| PlayerServiceStub | `services/services/player/ipc/stub/` | PlayerServiceStub::OnRemoteRequest/DoFreeze/DoUnFreeze |
| PlayerServiceStubMem | `services/services/player/player_mem_manage/` | PlayerServiceStubMem::Create |
| PlayerListenerCallback | `services/services/player/ipc/` | PlayerListenerCallback::OnInfo/OnError |
| PlayerListenerProxy | `services/services/player/ipc/proxy/` | PlayerListenerProxy, isFrozen_ |
| PlayerListenerStub | `services/services/player/ipc/stub/` | PlayerListenerStub::OnRemoteRequest/OnInfo/OnError/OnVideoSizeChanged |
| IStandardPlayerService | `services/services/player/ipc/i_standard_player_service.h` | IStandardPlayerService |
| IStandardPlayerListener | `services/services/player/ipc/i_standard_player_listener.h` | IStandardPlayerListener |
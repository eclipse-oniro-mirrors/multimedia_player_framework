# 服务层实体

> PlayerServer、PlayerServerMem、MediaServiceFactory 等服务端核心类

## 实体概念

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| PlayerServer | 播放器服务端核心类，实现 IPlayerService + IPlayerEngineObs | 8 状态有限状态机；PlayerServerTaskMgr 异步队列；ConfigInfo 统一配置；互斥锁保护状态/引擎/配置；通过 IPlayerEngine 接口操作引擎 | 核心服务类 |
| PlayerServerMem | 内存管理扩展，继承 PlayerServer | RecoverConfigInfo 状态保存；前台回收本地资源释放；后台回收网络资源释放；恢复本地资源恢复 | PlayerServer 扩展 |
| PlayerMemManage | 系统级内存管理单例 | HandleForceReclaim 强制回收；HandleOnTrim 按级别回收；RecoverByMemManage 恢复 | 全局单例 |
| MediaServiceFactory | 全局单例工厂，创建/销毁播放器服务实例 | CreatePlayerService IPC 创建；DestroyPlayerService 销毁 | 全局工厂 |
| MediaServer | 系统能力入口，注册播放服务/录制服务/屏幕录制服务到 SAMGR | OnStart/OnStop 管理服务生命周期 | 系统能力服务 |
| MediaServerManager | 服务端管理器，维护播放器/录制器实例映射表 | CreatePlayerService/DestroyPlayerService 创建/销毁/查询接口 | 系统能力基础设施 |
| MediaClient | 客户端系统能力代理，获取媒体服务远程对象 | GetMediaServerProxy 获取代理；处理服务死亡通知 | 系统能力基础设施 |
| MediaDeathRecipient | 监控服务端进程死亡，触发客户端清理 | OnRemoteDied 释放代理、通知上层 OnError | 系统能力基础设施 |
| PlayerServerCommonEventReceiver | 监听系统公共事件，转发给 PlayerServer | 账号切换等系统事件 | 系统事件处理 |
| AccountSubscriber | 监听账号切换事件 | DispatchEvent → 通知播放器清理资源 | 系统事件处理 |
| AppStateListener | 监听应用前后台切换 | 强制回收/按级别回收 触发内存回收 | 系统事件处理 |
| AudioBackgroundAdapter | 监听音频后台静音事件 | 适配后台策略 | 系统事件处理 |
| AVsessionBackground | 监听 AVSession 事件 | 管理后台播放行为 | 系统事件处理 |

## 上下文与场景

### 交互流程

**播放器创建流程**：

```
应用 → IPC → MediaServiceFactory::CreatePlayerService
  → new PlayerServerMem()
  → EngineFactoryRepo::CreatePlayerEngine(sceneType)
  → 返回 PlayerServiceStub (IPC 端)
```

**播放控制流程**：

```
应用 → IPC → PlayerServiceStub::OnRemoteRequest
  → PlayerServer::PrepareAsync / Play / Pause / Stop / Seek
  → TaskMgr 异步队列执行
  → IPlayerEngine → HiPlayerImpl
```

**内存回收流程**：

```
系统内存压力 → AppStateListener
  → PlayerMemManage::HandleOnTrim / HandleForceReclaim
  → PlayerServerMem::本地资源释放 / 网络资源释放
  → RecoverConfigInfo 保存状态
  → 后台恢复时 RecoverByMemManage
```

### 状态流转

**PlayerServer 8 状态有限状态机**：

| 状态类 | 允许的操作 |
|--------|-----------|
| 空闲状态 | SetSource, Reset |
| 已初始化状态 | PrepareAsync, Reset |
| 准备中状态 | 无（等待回调） |
| 已准备状态 | Play, Seek, Reset |
| 播放中状态 | Pause, Stop, Seek, SetSpeed |
| 暂停状态 | Play, Stop, Seek, Reset |
| 已停止状态 | Reset |
| 播放完成状态 | Play, Seek, Stop, Reset |

### 异常处理路径

| 异常场景 | 处理方式 |
|---------|---------|
| 服务端进程崩溃 | 客户端-服务端双进程隔离，客户端通过死亡通知感知并上报错误 |
| 系统内存压力 | PlayerMemManage 分级回收：后台优先释放解码器/网络资源，前台保存状态后重置引擎 |
| 账号切换 | AccountSubscriber 监听事件，清理当前账号播放器资源 |
| 应用前后台切换 | AppStateListener 触发强制回收/按级别回收，后台冻结 IPC 回调 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 业务规则 | PlayerServer 所有操作必须经过状态机校验，非法操作返回 MSERR_INVALID_STATE |
| 业务规则 | ConfigInfo 在 PrepareAsync 前设置，HandlePrepare 时一次性应用 |
| 性能约束 | 所有播放操作通过 TaskMgr 异步执行，IPC 线程快速返回不阻塞 |
| 安全与隐私约束 | 互斥锁保护状态/引擎/配置，防止并发操作导致数据竞争 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上层依赖 | [[ipc-layer-entities]] — 通过 IPC 存根/代理接收客户端请求 |
| 下游影响 | [[engine-layer-entities]] — 通过 IPlayerEngine 接口控制引擎 |
| 平级关联 | PlayerMemManage ↔ PlayerServerMem — 前者管理系统级回收策略，后者执行具体回收操作 |
| 概念对比 | PlayerServer vs PlayerServerMem — 后者继承前者并扩展内存管理能力 |

## 数据模型

### RecoverConfigInfo

PlayerServerMem 用于保存/恢复播放状态的配置结构体：

| 字段 | 说明 |
|------|------|
| currState / sourceType / url / dataSrc | 播放状态与源 |
| fd / offset / size | 文件描述符源参数 |
| leftVolume / rightVolume / speedMode | 音量与速度 |
| surface / loop / videoScaleType | 视频与循环 |
| currentTime / playbackPosition | 播放位置（恢复时 Seek 回此位置） |
| videoTrack / audioTrack / duration | 轨道信息 |

### PlayerMemManage 数据结构

playerManage_ 映射表 (进程ID → 应用播放器信息)：按进程标识管理播放器实例信息。

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| PlayerServer | `services/services/player/player_server.h/.cpp` | PlayerServer::PrepareAsync/Play/Pause/Stop/Seek |
| PlayerServer 状态机 | `services/services/player/player_server_state.h/.cpp` | BaseState, IdleState, InitializedState, PreparedState, PlayingState, PausedState, StoppedState, PlaybackCompletedState |
| PlayerServerMem | `services/services/player/player_mem_manage/` | PlayerServerMem::本地资源释放/恢复 |
| PlayerMemManage | `services/services/player/player_mem_manage.h/.cpp` | PlayerMemManage::HandleForceReclaim/HandleOnTrim/RecoverByMemManage |
| MediaServiceFactory | `services/services/player/` | MediaServiceFactory::CreatePlayerService/DestroyPlayerService |
| MediaServer | `services/services/player/server/media_server.cpp` | MediaServer::OnStart/OnStop |
| MediaServerManager | `services/services/player/server/media_server_manager.cpp` | MediaServerManager::CreatePlayerService/DestroyPlayerService |
| MediaClient | `services/services/player/ipc/client/media_client.cpp` | MediaClient::GetMediaServerProxy |
| MediaDeathRecipient | `services/services/player/ipc/client/media_death_recipient.cpp` | MediaDeathRecipient::OnRemoteDied |
| PlayerServerCommonEventReceiver | `services/services/player/player_server_event_receiver.h/.cpp` | PlayerServerCommonEventReceiver |
| AccountSubscriber | `services/services/player/subscriber/` | AccountSubscriber::OnReceiveEvent |
| AppStateListener | `services/services/player/` | AppStateListener |
| AudioBackgroundAdapter | `services/services/player/` | AudioBackgroundAdapter |
| AVsessionBackground | `services/services/player/` | AVsessionBackground |
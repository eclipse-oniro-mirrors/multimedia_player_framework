# 播放器完整生命周期

> 从创建到销毁的全流程，包含状态机、任务队列、引擎交互。开发核心参考。

## 一、8状态状态机

PlayerServer 采用 **8 状态有限状态机** 管理生命周期：

```
                    SetSource()
   IDLE ──────────────────────→ INITIALIZED
     ↑                              │
     │ Reset()              PrepareAsync()
     │                              ↓
     │                         PREPARING
     │                              │
     │              OnInfo(PREPARED) ↓
     │                         PREPARED
     │                              │ Play()
     │                              ↓
     │         Pause()         STARTED
     │           ↑                │
     │           │                │ Pause()
     │           └────────────────┘
     │                              │ Stop()
     │                              ↓
     └────────────────────      STOPPED
     │ Reset()              │
     └──────────────────────┘
     
     任何状态 ──OnError()──→ ERROR ──Reset()──→ IDLE
```

### 状态说明

| 状态 | 含义 | 允许的操作 |
|------|------|-----------|
| IDLE | 初始/重置后状态 | SetSource(), Reset() |
| INITIALIZED | 已设置播放源 | PrepareAsync(), Reset() |
| PREPARING | 异步准备中 | 无（等待准备完成回调） |
| PREPARED | 准备完成，可播放 | Play(), SeekTo(), Reset() |
| STARTED | 正在播放 | Pause(), Stop(), SeekTo(), SetSpeed(), SetVolume() |
| PAUSED | 暂停 | Play(), Stop(), SeekTo(), Reset() |
| STOPPED | 停止 | Reset() |
| ERROR | 错误 | Reset() |

### 状态转换约束（铁律）

1. **必须顺序**：IDLE → INITIALIZED → PREPARING → PREPARED → STARTED
2. **Play/Pause可逆**：STARTED ↔ PAUSED
3. **Stop回到STOPPED**：STARTED/PAUSED → STOPPED，必须Reset后才能重新播放
4. **Error必须Reset**：ERROR状态只能执行Reset()回到IDLE
5. **SetSource只在IDLE**：其他状态调用SetSource()会返回错误

## 二、完整生命周期流程

### 2.1 创建播放器

```
应用 → AVPlayer::Create() → PlayerClient::Create(ipcProxy)
  → IPC → PlayerServiceStub::CreateListener()
  → PlayerServer初始化：
    - PlayerServerStateMachine初始化为IDLE
    - PlayerServerTaskMgr创建
    - ConfigInfo默认值设置
  → 返回PlayerClient给应用
```

### 2.2 设置播放源

```
应用 → PlayerClient::SetSource(url)
  → IPC → PlayerServiceStub::SetSource()
  → PlayerServer::SetSource()：
    - 检查状态 == IDLE
    - InitPlayEngine()：通过EngineFactoryRepo打分选择引擎
    - engine_->SetSource(source)
    - 状态 → INITIALIZED
```

**三种媒体源**：

| 类型 | 说明 | 调用方式 |
|------|------|---------|
| URL源 | 文件路径/网络地址 | SetSource(url) |
| FD源 | 文件描述符 | SetSource(fd, offset, size) |
| DataSource源 | 自定义数据源回调 | SetSource(dataSource) |

### 2.3 异步准备

```
应用 → PlayerClient::PrepareAsync()
  → IPC → PlayerServer::PrepareAsync()
  → PlayerServerTaskMgr::Enqueue(HandlePrepare)  ← 异步任务入队
  → HandlePrepare执行：
    - 应用ConfigInfo配置到引擎
    - engine_->PrepareAsync()
    - 状态 → PREPARING
  → 引擎准备完成回调：
    - engine_ → OnInfo(PLAYER_PREPARED)
    - PlayerServer状态 → PREPARED
    - 通过ListenerProxy IPC通知客户端
```

### 2.4 开始播放

```
应用 → PlayerClient::Play()
  → IPC → PlayerServer::Play()
  → PlayerServerTaskMgr::Enqueue(HandlePlay)
  → HandlePlay执行：
    - engine_->Play()
    - 状态 → STARTED
  → Pipeline开始数据流：
    Source → DemuxerFilter → DecoderFilter → SinkFilter → 输出
```

### 2.5 暂停播放

```
应用 → PlayerClient::Pause()
  → IPC → PlayerServer::Pause()
  → PlayerServerTaskMgr::Enqueue(HandlePause)
  → HandlePause执行：
    - engine_->Pause()  ← Pipeline各Filter依次Pause
    - 状态 → PAUSED
```

### 2.6 停止与重置

```
应用 → PlayerClient::Stop()
  → 状态 → STOPPED
  → engine_->Stop()

应用 → PlayerClient::Reset()
  → engine_->Reset()
  → 释放引擎资源
  → 状态 → IDLE（可重新SetSource）
```

## 三、任务队列机制

PlayerServer 所有操作通过 **PlayerServerTaskMgr** 异步执行：

| 机制 | 说明 |
|------|------|
| 任务入队 | 调用方线程只负责将操作封装为TaskItem入队，立即返回 |
| 异步执行 | TaskMgr工作线程从队列取出任务执行，避免阻塞调用方 |
| 两阶段任务 | TwoPhaseTaskItem支持Prepare/Execute分离，用于Seek等需要准备的操作 |
| 任务去重 | 连续相同类型的任务会合并/替换，避免冗余执行 |

**为什么要异步？** IPC调用本身有序列化开销，如果在IPC线程上同步执行耗时操作（如引擎初始化），会阻塞IPC线程池导致服务端卡死。

## 四、配置管理

ConfigInfo 在创建后、PrepareAsync前设置，在HandlePrepare时一次性应用到引擎：

| 配置项 | 方法 | 说明 |
|--------|------|------|
| 音量 | SetVolume() | 0.0 ~ 1.0 |
| 循环 | SetLooping() | 是否单曲循环 |
| 播放速度 | SetSpeed() | 倍速播放 |
| Seek模式 | 不在ConfigInfo | 通过SeekTo()参数指定 |

## 五、回调链路

播放器状态变化通过回调链路通知应用：

```
引擎事件 → PlayerServer::OnInfo()
  → PlayerListenerCallback::OnInfo()
  → PlayerListenerProxy::OnInfo()  ← IPC发送
  → PlayerListenerStub::OnInfo()   ← IPC接收
  → PlayerCallback::OnInfo()       ← 应用层回调
```

| 事件类型 | 触发时机 |
|---------|---------|
| PLAYER_PREPARED | PrepareAsync完成 |
| PLAYER_PLAYBACK_COMPLETE | 播放到末尾 |
| PLAYER_SEEK_DONE | Seek完成 |
| PLAYER_BUFFERING_START/END | 缓冲开始/结束 |
| PLAYER_ERROR | 发生错误 |
| PLAYER_INFO | 信息通知（如音视频渲染首帧） |

## 知识关联

- [[architecture]] - 架构总览
- [[ipc-communication]] - IPC通信与回调详解
- [[pipeline-architecture]] - Pipeline架构详解
- [[seek-architecture]] - Seek架构详解
- [[player-server]] - PlayerServer实体详情
- [[player-server-state-machine]] - 状态机详情
- [[player-server-task-mgr]] - 任务管理器详情

# IPC通信与回调机制

> Client-Server通信架构、回调链路、异常恢复与演进。

## 一、IPC通信架构

播放器框架采用 **Client-Server 双进程架构**，通过 OHOS IPC (Binder) 通信：

```
应用进程                              媒体服务进程
┌──────────────────┐                ┌──────────────────────────┐
│ PlayerClient     │                │ PlayerServiceStub        │
│   └─proxy_ ──────│── IPC调用 ────→│   └─转发给PlayerServer   │
│                  │                │                          │
│ PlayerCallback   │←── IPC回调 ────│ PlayerListenerProxy      │
│   └─应用层回调    │                │   └─事件推送              │
└──────────────────┘                └──────────────────────────┘
```

### 1.1 调用通路（Client → Server）

```
应用 → PlayerClient::Play()
  → PlayerServiceProxy::Play()          ← 序列化参数
  → IPC Binder 驱动
  → PlayerServiceStub::OnRemoteRequest() ← 反序列化
  → PlayerServer::Play()                ← 执行业务逻辑
```

### 1.2 回调通路（Server → Client）

```
PlayerServer::OnInfo() → PlayerListenerCallback::OnInfo()
  → PlayerListenerProxy::OnInfo()       ← 序列化事件
  → IPC Binder 驱动
  → PlayerListenerStub::OnRemoteRequest() ← 反序列化
  → PlayerCallback::OnInfo()            ← 应用层回调
```

## 二、IPC接口定义

### 2.1 IStandardPlayerService（调用接口）

Client → Server 的播放控制接口：

| 方法 | 说明 |
|------|------|
| SetSource() | 设置播放源 |
| PrepareAsync() | 异步准备 |
| Play() / Pause() / Stop() | 播放控制 |
| SeekTo() | Seek跳转 |
| SetVolume() / SetSpeed() | 参数设置 |
| SetLooping() | 循环模式 |
| SetSurface() | 设置视频渲染Surface |
| Reset() / Release() | 重置/释放 |

### 2.2 IStandardPlayerListener（回调接口）

Server → Client 的事件通知接口：

| 方法 | 说明 |
|------|------|
| OnInfo() | 信息通知（准备完成、Seek完成等） |
| OnError() | 错误通知 |
| OnVideoSizeChanged() | 视频尺寸变化 |
| OnBufferingUpdate() | 缓冲进度更新 |
| OnRewindToComplete() | Seek完成 |
| SetFreezeFlag() | 冻结/解冻标志 |

## 三、回调机制详解

### 3.1 回调对象链路

```
PlayerServer
  └─ playerCb_ (PlayerCallback)
      └─ PlayerListenerCallback（桥接类）
          └─ listenerProxy_ (IStandardPlayerListener.Proxy)
              └─ IPC → PlayerListenerStub
                  └─ PlayerCallback（应用层回调）
```

### 3.2 关键回调事件

| 事件 | 触发点 | 说明 |
|------|--------|------|
| PLAYER_PREPARED | 引擎OnInfo回调 | 准备完成 |
| PLAYER_SEEK_DONE | SeekAgent | Seek完成 |
| PLAYER_PLAYBACK_COMPLETE | 引擎OnInfo回调 | 播放到末尾 |
| PLAYER_BUFFERING_START/END | Source/Downloader | 缓冲状态变化 |
| PLAYER_ERROR | 引擎OnError回调 | 播放错误 |
| PLAYER_VIDEO_RENDERING_START | 首帧渲染 | 视频首帧显示 |
| PLAYER_AUDIO_RENDERING_START | 音频首帧 | 音频首帧播放 |

### 3.3 回调线程

- **服务端回调**：在引擎工作线程上触发，通过IPC发送到客户端
- **客户端回调**：在IPC Binder线程上接收，调用应用层PlayerCallback
- **重要约束**：应用层回调中不应执行耗时操作，否则会阻塞IPC线程

## 四、IPC异常恢复

### 4.1 服务端死亡检测

```
PlayerClient 注册 DeathRecipient
  → 服务端进程死亡 → DeathRecipient::OnRemoteDied()
  → 通知应用层 PLAYER_ERROR(SERVICE_DIED)
  → 应用可选择重建播放器
```

### 4.2 客户端死亡清理

```
PlayerServiceStub 监控客户端生命周期
  → 客户端进程死亡 → Stub 清理对应 PlayerServer 实例
  → 释放引擎资源
```

### 4.3 IPC调用失败处理

| 场景 | 处理方式 |
|------|---------|
| IPC调用返回错误码 | PlayerClient 将错误码转换为 PlayerError 回调应用 |
| IPC超时 | 同步IPC调用有超时机制，超时后返回错误 |
| 远端异常 | 服务端try-catch捕获，通过OnError回调通知客户端 |

## 五、IPC序列化开销与优化

### 5.1 开销来源

| 环节 | 开销 |
|------|------|
| 参数序列化 | MessageParcel::WriteInt32/WriteString等 |
| 内核态切换 | Binder驱动的用户态↔内核态切换 |
| 数据拷贝 | 参数和返回值的内存拷贝 |
| 反序列化 | MessageParcel::ReadInt32/ReadString等 |

### 5.2 优化策略

| 策略 | 实现 |
|------|------|
| 异步任务队列 | PlayerServer通过TaskMgr异步执行，IPC线程快速返回 |
| 批量参数 | ConfigInfo一次性传递多个配置项，减少IPC次数 |
| 状态机驱动 | 仅状态变化时触发IPC，避免轮询 |
| 回调去重 | 同类型事件仅回调一次（如连续缓冲更新） |

## 六、IPC通信演进

| 阶段 | 变化 |
|------|------|
| 早期 | 同步IPC + 同步回调，阻塞调用方线程 |
| 演进1 | 异步任务队列，IPC线程快速返回 |
| 演进2 | 回调链路优化，减少不必要的IPC回调 |
| 当前 | 完整的异常恢复机制，DeathRecipient监控 |

## 知识关联

- [[architecture]] - 架构总览
- [[player-lifecycle]] - 播放器生命周期
- [[player-service-stub]] - Stub详情
- [[player-service-proxy]] - Proxy详情
- [[player-listener-stub]] - ListenerStub详情
- [[player-listener-proxy]] - ListenerProxy详情
- [[player-callback-mechanism]] - 回调机制详情
- [[ipc-stub-proxy-pattern]] - IPC模式详情
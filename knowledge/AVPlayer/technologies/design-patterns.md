# 设计模式与架构解耦

> PlayerServer 中应用的设计模式、状态机、解耦机制和桥接层。

## 一、PlayerServer 设计模式总览

| 模式 | 角色 | 关键对象 | 说明 |
|------|------|---------|------|
| 状态模式 | PlayerServer = 上下文, BaseState 子类 = 具体状态 | 8 个 BaseState 子类 | 消除 if-else/switch-case，每状态类仅实现允许的操作 |
| 单例模式 | 全局唯一实例 | AudioBackgroundAdapter, PlayerMemManage | std::call_once 线程安全延迟初始化 |
| 策略模式 | PlayerServerMem = 上下文, 回收策略 = 具体策略 | isLocalResource_ 决定 Local/Network 策略 | 按资源类型选择回收策略 |
| 观察者模式 | PlayerServer = 主题, PlayerCallback = 观察者 | playerCb_ | 状态变更通知应用层 |
| 工厂模式 | 静态工厂方法 | PlayerServer::Create(), PlayerServiceStub::Create() | 封装创建逻辑 |

- **设计原则**：单一职责、开闭原则、依赖倒置
- **代码路径**：`services/services/player/player_server.h/.cpp`

## 二、PlayerServer 8 状态状态机

### 状态定义

| 状态 | 允许的操作 | 状态类 |
|------|-----------|--------|
| IDLE | SetSource, Reset | IdleState |
| INITIALIZED | PrepareAsync, Reset | InitializedState |
| PREPARING | 无（等待回调） | PreparingState |
| PREPARED | Play, Seek, Reset | PreparedState |
| STARTED/PLAYING | Pause, Stop, Seek, SetSpeed | PlayingState |
| PAUSED | Play, Stop, Seek, Reset | PausedState |
| STOPPED | Reset | StoppedState |
| PLAYBACK_COMPLETE | Play, Seek, Stop, Reset | PlaybackCompletedState |

### 状态机机制

- **BaseState**：抽象接口，定义所有状态操作
- **ChangeState**：确保 StateExit/StateEnter 生命周期
- **ReportInvalidOperation**：不支持操作返回 MSERR_INVALID_STATE
- **PlayerServerStateMachine**：上下文，维护当前状态

## 三、观察者模式 — 事件通知

### 播放器事件链

```
PlayerServer::OnInfo
  → PlayerListenerCallback::OnInfo
  → PlayerListenerProxy::OnInfo (IPC)
  → PlayerListenerStub::OnInfo
  → PlayerCallback::OnInfo
  → 应用层
```

### 引擎事件链

```
HiPlayerImpl → HiPlayerCallbackLooper (异步线程安全)
  → IPlayerEngineObs::OnInfo / OnError
  → PlayerServer
```

### 关键对象

| 对象 | 说明 |
|------|------|
| PlayerCallback | 应用层观察者接口 |
| PlayerImplCallback | 代理桥接层，API 版本适配 |
| HiPlayerCallbackLooper | 引擎异步事件分发循环 |
| IPlayerEngineObs | 引擎观察者接口 |

## 四、代理模式 — 回调桥接

**PlayerImplCallback** 作为 PlayerImpl 与 PlayerCallback 之间的代理：

| 特性 | 说明 |
|------|------|
| API 版本适配 | apiVersion_ 检查，API 14 以下 IO 错误码降级 |
| 弱引用避免循环 | weak_ptr\<PlayerImpl\> 防止循环引用 |
| 错误码转换 | MSErrCodeToAVErrCodeApi9 映射 |

## 五、策略模式 — Seek 拖拽

### 拖拽策略体系

```
DraggingDelegator (抽象策略)
├── SeekContinuousDelegator (连续拖拽)
│   ├── UpdateSeekPos → 更新位置
│   ├── ConsumeVideoFrame → 消费帧预览
│   ├── IsVideoStreamDiscardable → 是否可丢帧
│   └── monitorTask_ → 监控拖拽状态
└── SeekClosestDelegator (精准拖拽)
    ├── seekTimeMsQue_ → 请求队列
    ├── seekTask_ → 后台 Seek 线程
    └── DoSeek → 执行实际 Seek
```

### DraggingDelegatorFactory

| DraggingMode | 创建的委托 |
|-------------|-----------|
| DRAGGING_NONE | 无 |
| DRAGGING_CLOSEST | SeekClosestDelegator |
| DRAGGING_CONTINUOUS | SeekContinuousDelegator |

## 六、工厂模式

### PlayerFactory

| 方法 | 说明 |
|------|------|
| CreatePlayer(producer) | 创建 PlayerImpl 实例 |
| PlayerProducer::INNER | 内部生产者 |
| PlayerProducer::CAPI | C API 生产者 |

### DraggingDelegatorFactory

- CreateDelegator(mode) → 选择 SeekContinuous 或 SeekClosest 委托

### 动态工厂 — EngineFactoryRepo

```
EngineFactoryRepo::CreatePlayerEngine(sceneType)
  → Score() 打分选择最优工厂
  → EngineFactory::CreatePlayerEngine()
  → dlopen("libhistreamer_engine.z.so")
  → dlsym("CreateEngineFactory")
  → 返回引擎实例
```

| 加载路径 | 说明 |
|---------|------|
| /system/lib64/media | 64位引擎 SO |
| /system/lib/media | 32位引擎 SO |

## 七、IPC Stub/Proxy 模式

### 双向 IPC 通道

| 方向 | 调用端 | 服务端 | 说明 |
|------|--------|--------|------|
| 正向 | PlayerServiceProxy | PlayerServiceStub | Client → Server 请求 |
| 反向 | PlayerListenerProxy | PlayerListenerStub | Server → Client 回调 |

### Stub 分发机制

- **OnRemoteRequest** → playerFuncs_ 映射表 → 处理函数
- **Proxy** → SendRequest → Binder 序列化参数

## 八、作用域守卫模式

| 宏 | 说明 |
|----|------|
| ON_SCOPE_EXIT | 设置异常恢复逻辑 |
| CANCEL_SCOPE_EXIT_GUARD | 成功路径取消恢复 |

**应用场景**：SwitchToIndex、SeekForInt64 等需要异常安全回滚的操作

## 九、架构解耦机制

### 1. 服务与引擎解耦

| 层 | 职责 | 说明 |
|----|------|------|
| Service Server | IPC + 状态机 | 可独立升级 |
| Engine | 核心处理 | 热插拔、多实例 |

### 2. 契约层（Contract Layer）

| 子层 | 内容 | 说明 |
|------|------|------|
| Inner API Headers | C++ 抽象接口 | 服务间交互 |
| Kits API Headers | C Native API + JS Napi | 外部使用 |

- **Inner API**：Player/Recorder/ScreenCapture/TransCoder 抽象接口
- **Kits API**：OH_AVPlayer/OH_AVRecorder/OH_AVScreenCapture 不透明指针

### 3. 访问层/桥接层

| 桥接类型 | 说明 | 关键对象 |
|---------|------|---------|
| JS/Napi Bridge | ArkTS/JS 异步编程 + 线程安全回调 | AVPlayerNapi, TaskQueue, CommonNapi |
| CJ/FFI Bridge | 仓颉 FFI 接口 + 对象生命周期管理 | CJAVPlayer, FFIData |
| Taihe Bridge | Taihe 框架 Native 能力桥接 | — |

## 知识关联

- [[architecture]] - 架构总览
- [[service-layer]] - 服务层实体
- [[ipc-layer-entities]] - IPC层实体
# 设计模式与架构解耦

> ScreenCaptureServer 设计模式总览、与 AVPlayer 设计对比、架构解耦机制。

## 一、设计模式总览

| 模式 | 实现类 | 说明 |
|------|--------|------|
| 状态模式 | 能力位图 IsState(cap) | 替代 AVPlayer 的 BaseState 子类继承体系 |
| 单例模式 | ServerManager、MonitorServer | 全局唯一实例管理 |
| 观察者模式 | 回调基类 + ListenerManager | 事件回调 + 系统监听器 |
| 工厂模式 | ScreenCaptureFactory、ControllerFactory | 实例创建 |
| 代理模式 | CallbackProxy、ListenerCallback | 回调桥接 |
| Wrapper 模式 | ListenerManager 各 Wrapper | 系统监听器适配 |
| 依赖注入 | ServiceProviders 接口 | 服务依赖抽象 |
| Stub/Proxy | IPC 接口对 | 跨进程通信 |
| 作用域守卫 | ON_SCOPE_EXIT / CANCEL_SCOPE_EXIT_GUARD | 资源安全释放 |

## 二、能力位图状态机（与 Player 状态类对比）

| 维度 | AVPlayer | ScreenCapture |
|------|----------|---------------|
| 状态管理 | 8 个 BaseState 子类 | 7 状态枚举 + 状态-能力映射 |
| 状态校验 | state->CheckState(operation) | IsState(cap) 位与判断 |
| 状态转换 | 显式 state = NewState() | captureState = 新状态枚举 |
| 能力组合 | 状态类方法决定 | Capability 位组合决定 |

| 维度 | 能力位图 | 状态类继承 |
|------|---------|-----------|
| 扩展性 | 新增状态需修改枚举+映射 | 新增状态类即可 |
| 查询效率 | O(1) 位与运算 | 虚函数调用 |
| 代码简洁度 | 简洁，一个 IsState 覆盖所有 | 每个状态类独立实现 |
| 跨状态能力 | 天然支持（一状态多 Capability） | 需继承链或多接口 |

## 三、观察者模式 — 事件通知链

- **录屏事件观察者**：ScreenCaptureServer 持有回调代理，通过 IPC 桥接转发到应用层；ListenerManager 管理 9 类系统监听器 Wrapper，按 ListenerFlag 位图按需注册。
- **Monitor 观察者**：MonitorServer 持有监听器集合，录屏开始/结束/死亡时遍历通知。

## 四、Wrapper 模式 — 监听器管理

ListenerManager 通过 Wrapper 适配不同系统监听器接口：

| Wrapper | 事件 |
|---------|------|
| SessionLifecycleListener | 窗口 FOREGROUND/BACKGROUND/DESTROYED |
| WindowInfoListener | 窗口信息变化 |
| RecordDisplayListener | 录制显示器变化 |
| PrivateWindowListener | 隐私窗口变化 |
| ScreenConnectListener | 屏幕连接/断开 |
| LanguageSwitchSubscriber | 语言切换 |
| AccountObserver | 账户切换 |
| InCallObserver | 通话状态 |
| AudioRendererCallback | 音频渲染器状态 |

每个 Wrapper 持有事件监听接口的弱引用，将系统事件转发给 ScreenCaptureServer。通过 RegisterListeners(flags) 按需注册，UnregisterListeners(flags) 按需注销。

## 五、代理模式 — 回调桥接

- **CallbackProxy**：服务端内部回调代理，实现 8 个回调接口转发给实际回调；bufferActive 控制缓冲回调是否通知应用，停止录屏时关闭。
- **ListenerCallback**：将应用层回调接口适配为 IPC 接口，实现跨进程回调传输。

## 六、工厂模式

| 工厂 | 作用 |
|------|------|
| ScreenCaptureFactory | InnerAPI 层创建实例（应用调用） |
| ScreenCaptureControllerFactory | 创建 Controller 实例 |
| CreateScreenCaptureServer (extern C) | 服务端创建 Server 实例 |

## 七、IPC Stub/Proxy 模式

| 接口 | Stub（服务端） | Proxy（客户端） |
|------|----------------|----------------|
| Service | ServiceStub | ServiceProxy |
| Listener | ListenerStub | ListenerProxy |
| Controller | ControllerStub | ControllerProxy |
| MonitorService | MonitorServiceStub | MonitorServiceProxy |
| MonitorListener | MonitorListenerStub | MonitorListenerProxy |

## 八、作用域守卫模式

ON_SCOPE_EXIT / CANCEL_SCOPE_EXIT_GUARD 用于关键流程的资源安全释放：异常路径守卫自动执行清理（销毁虚拟屏幕、停止缓冲线程、释放）；正常路径取消守卫。

## 九、架构解耦机制

### 9.1 服务与采集实现解耦

ScreenCaptureServer 不经过引擎层，直接调用 Rosen（显示管理）和 AudioCapturer（音频采集），CAPTURE_FILE 模式复用 Recorder 引擎。与 AVPlayer 不同，录屏模块无 EngineFactory / Pipeline 架构。

### 9.2 契约层（InnerAPI Headers）

| 头文件 | 接口类 | 说明 |
|--------|--------|------|
| interfaces/inner_api/native/screen_capture.h | ScreenCapture、ScreenCaptureCallBack、ScreenCaptureFactory | 录屏主接口 |
| interfaces/inner_api/native/screen_capture_controller.h | ScreenCaptureController | Picker 用户选择控制器 |
| interfaces/inner_api/native/screen_capture_monitor.h | ScreenCaptureMonitor、ScreenCaptureMonitorListener | 录屏状态监控 |

### 9.3 依赖注入

通过 ServiceProviders 抽象外部依赖（Monitor/Recorder/AccountObserver/InCallObserver），测试时可注入 Mock。

## 知识关联

- [capture-lifecycle](capture-lifecycle.md) - 录屏完整生命周期
- [ipc-communication](ipc-communication.md) - IPC 通信与回调机制
- [privacy-and-permission](privacy-and-permission.md) - 隐私保护与权限机制
- [flows](flows.md) - 关键流程详解
- [evolution](evolution.md) - 模块演进记录

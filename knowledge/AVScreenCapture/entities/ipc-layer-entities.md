# IPC 层实体

> Client、存根/代理、监听器等跨进程通信实体

## 实体概念

| 实体名称 | 实体定义 | 类型/分类 |
|---------|---------|----------|
| ScreenCaptureClient | 应用进程录屏代理，持有调用代理 + 回调存根 + 死亡通知 | 客户端 |
| ScreenCaptureServiceProxy/Stub | 调用通路：Proxy 序列化参数发起 IPC，Stub 反序列化分发到 Server | 客户端代理/服务端存根 |
| ScreenCaptureListenerCallback | 桥接类，将应用回调转发到 IPC 通路 | 回调通路 |
| ScreenCaptureListenerProxy/Stub | 回调通路：Proxy 序列化事件发起 IPC，Stub 反序列化调用应用回调 | 回调通路代理/存根 |
| IStandardScreenCaptureService | 客户端→服务端 录屏控制接口 | IPC 接口定义 |
| IStandardScreenCaptureListener | 服务端→客户端 事件通知接口 | IPC 接口定义 |
| ScreenCaptureControllerClient/Stub/Proxy | 用户选择控制器客户端/存根/代理 | Controller 通路 |
| IStandardScreenCaptureController | 用户选择控制接口 | IPC 接口定义 |
| ScreenCaptureMonitorClient/Stub/Proxy | Monitor 客户端/服务端存根/代理 | Monitor 通路 |
| IStandardScreenCaptureMonitorService | Monitor 控制接口 | IPC 接口定义 |
| IStandardScreenCaptureMonitorListener | Monitor 回调接口 | IPC 接口定义 |
| ScreenCaptureMonitorListenerProxy/Stub/Callback | Monitor 回调双向代理/桥接 | 回调通路 |

> 消息码编号表详见 [ipc-communication](../technologies/ipc-communication.md)（IPC 契约定义）。

## 交互流程

**IPC 调用通路（客户端 → 服务端）**：
应用调用 → Client → ServiceProxy(序列化) → IPC Binder → ServiceStub(反序列化+分发) → ScreenCaptureServer

**IPC 回调通路（服务端 → 客户端）**：
服务端事件 → CallbackProxy(服务端内部回调代理) → ListenerCallback(桥接) → ListenerProxy(序列化) → IPC Binder → ListenerStub(反序列化) → 应用层回调

**Monitor 回调通路（服务端 → 客户端）**：
MonitorServer → MonitorListenerProxy(序列化) → IPC Binder → MonitorListenerStub(反序列化) → 应用层监听器

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 系统限制 | IPC 传输数据必须通过 MessageParcel 序列化，不可共享裸指针 |
| 业务规则 | Surface 通过序列号传递，不直接跨进程共享 Surface 对象 |
| 业务规则 | 服务端回调代理使用读写锁保护，可控制缓冲回调开关 |
| 安全与隐私 | 服务端 Stub 检查调用方权限 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上层依赖 | [api-layer](api-layer.md) — Impl 持有 Client 发起 IPC |
| 下游影响 | [service-layer](service-layer.md) — Stub 分发请求到 Server |
| 消息码契约 | [ipc-communication](../technologies/ipc-communication.md) — 4 组 IPC 接口消息码表 |
| 概念对比 | Service 接口(调用) vs Listener 接口(回调) — 双向 IPC 两个方向 |

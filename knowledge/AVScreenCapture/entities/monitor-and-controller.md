# Monitor 与 Controller 实体

> ScreenCaptureMonitor（全局监控）与 ScreenCaptureController（用户选择控制）实体

## 实体概念

| 实体名称 | 实体定义 | 类型/分类 |
|---------|---------|----------|
| ScreenCaptureMonitorServer | Monitor 服务端单例，追踪运行中录屏 PID 计数、监听器集合、系统录制器 PID | 全局单例 |
| ScreenCaptureMonitorClient | Monitor 客户端，持有 IPC 代理 + 回调存根 | 客户端 |
| ScreenCaptureMonitorListener | 监听器基类（录制开始/结束/进程死亡回调） | 监听器基类 |
| ScreenCaptureControllerServer | 用户选择处理服务端，按 sessionId 路由到对应 ScreenCaptureServer（解析在 Server 内） | 服务端类 |
| ScreenCaptureControllerClient | Controller 客户端，上报用户选择/查询可配置参数 | 客户端 |
| ScreenCaptureMonitorCallback / Napi | Monitor NAPI 回调适配/桥接 | NAPI 适配族 |

## 交互流程

**Monitor 监听流程（Server → MonitorServer → 通知监听器）**：
ScreenCaptureServer 启动 → 通知 MonitorServer → PID 计数+1 → 遍历监听器集合 → IPC 回调 → 应用层 OnScreenCaptureStarted(pid)
ScreenCaptureServer 停止 → 通知 MonitorServer → PID 计数-1（归零才通知 Finished）→ 通知 OnScreenCaptureFinished(pid)

**Monitor 查询流程**：
应用 → NAPI → Impl → Client → IPC → Stub → MonitorServer 查询 → 返回结果

**Controller 用户选择流程（Picker → Controller → Server）**：
系统 Picker UI → 应用上报用户选择 → ControllerImpl → Client → IPC → Stub → ControllerServer（按 sessionId 路由）→ ScreenCaptureServer 解析并配置录屏目标

> 上报字段约定与解析优先级详见 [service-layer](service-layer.md) 的 ReportUserChoice 解析与字段约定（Controller 仅路由，解析在 ScreenCaptureServer 内）。

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 单例约束 | MonitorServer 是进程级单例 |
| 线程安全 | MonitorServer 使用互斥锁保护 PID 计数和监听器集合 |
| 业务规则 | PID 计数为引用计数，同一 PID 多个录制实例时计数累加，计数归零才通知 Finished |
| 业务规则 | 系统录制器 PID 由专用接口设置，可判断是否系统录制器 |

## 数据模型

### ScreenCaptureMonitorEvent 枚举

| 值 | 说明 |
|----|------|
| SCREENCAPTURE_STARTED | 0 — 屏幕录制开始 |
| SCREENCAPTURE_STOPPED | 1 — 屏幕录制结束 |
| SCREENCAPTURE_DIED | 2 — 屏幕录制进程死亡 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上游依赖 | [api-layer](api-layer.md) — Monitor/Controller InnerAPI 接口 |
| 下游影响 | [service-layer](service-layer.md) — Server 通过内部接口通知 MonitorServer |
| 平级关联 | MonitorServer ↔ ScreenCaptureServer — 前者全局监控，后者单实例录制 |
| 平级关联 | ControllerServer ↔ ScreenCaptureServer — Controller 将用户选择分发到对应实例 |
| IPC 关联 | [ipc-layer-entities](ipc-layer-entities.md) — Monitor/Controller 的 IPC 存根/代理 |

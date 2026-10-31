# 服务层实体

> ScreenCaptureServer、ServerManager、监听器管理等服务端核心类

## 实体概念

| 实体名称 | 实体定义 | 类型/分类 |
|---------|---------|----------|
| ScreenCaptureServer | 屏幕录制服务端核心类，实现服务+事件监听接口 | 核心服务类 |
| ScreenCaptureServerManager | 单例管理器，管理实例映射表与实例数限制 | 全局单例 |
| ScreenCaptureServerBase | 基类，定义状态枚举/能力位图/统计事件信息 | 基类 |
| ScreenCaptureCallbackProxy | 服务端回调代理，读写锁保护，转发 8 种回调 | 回调代理 |
| ScreenCaptureListenerManager | 监听器统一管理，ListenerFlag 位图控制注册注销，管理多类系统监听器 Wrapper | 监听器管理 |
| IScreenCaptureEventListener | 事件监听纯虚接口，含窗口/隐私/屏幕/语言/账号/通话/音频渲染器等回调 | 纯虚接口 |
| IScreenCaptureServiceProviders | 依赖注入接口（获取 Monitor/创建 Recorder/获取 AccountObserver） | 依赖注入接口 |
| ScreenCaptureControllerServer | 用户选择处理服务端，按 sessionId 路由到对应 ScreenCaptureServer（解析在 Server 内） | 服务端类 |
| ScreenCaptureMonitorServer | Monitor 单例，追踪录屏进程 | 全局单例 |
| UIExtensionAbilityConnection | UI 扩展连接，管理授权弹窗生命周期 | UI 扩展 |

> 监听器 Wrapper（窗口生命周期/窗口信息/录制屏幕变更/隐私窗口/屏幕连接/语言切换/账号/通话/音频渲染器）均由 ListenerManager 统一注册，按 ListenerFlag 位图按需启用。

## 交互流程

**屏幕录制创建**：应用 → IPC → Stub → ScreenCaptureServer::Create → ServerManager 注册实例 → 返回 Client

**屏幕录制启动**：应用 → IPC → StartScreenCapture → 授权弹窗 → 创建虚拟屏幕 → 启动音频采集 → 启动视频/文件录制 → 后处理

**监听器注册**：SetupCaptureListeners → ListenerManager::RegisterListeners(flags) → 按位图注册各类 Wrapper → Wrapper 回调 → 事件监听接口 → ScreenCaptureServer

## ReportUserChoice 解析与字段约定

> `ReportAVScreenCaptureUserChoice`（Controller IPC 消息码 0）由 ControllerServer 按 sessionId 路由到对应 ScreenCaptureServer，`content` 为 JSON 字符串，解析在 Server 内完成。字段约定是 wire 兼容契约，修改字段名/取值/类型会 break 应用兼容性。

### choice 字段约定

`choice` 为字符串，取值：

| 取值 | 语义 |
|------|------|
| `"true"` | 允许 |
| `"false"` | 拒绝 |

### 字段互斥与解析优先级

字段互斥，一次上报只含一组，Server 按以下优先级解析：

| 优先级 | 字段组 | 说明 |
|------|------|------|
| 1 | `choice` | 用户授权选择，允许则附录制目标字段 |
| 2 | `stopRecording` | 停止录屏（STOPPED_BY_USER） |
| 3 | `appPrivacyProtectionSwitch` + `systemPrivacyProtectionSwitch` | 隐私开关变更 |

### 字段明细

| 字段 | 类型 | 说明 |
|------|------|------|
| `choice` | string ("true"/"false") | 用户授权选择，允许则解析录制目标 |
| `checkBoxSelected` | string ("true"/"false") | 隐私保护复选框，同时设置系统/应用隐私保护开关（choice 组附加） |
| `isInnerAudioBoxSelected` | string ("true"/"false") | 内录音频复选框（choice 组附加） |
| `stopRecording` | bool | true 则停止录屏（STOPPED_BY_USER） |
| `appPrivacyProtectionSwitch` | bool | 应用隐私保护开关 |
| `systemPrivacyProtectionSwitch` | bool | 系统隐私保护开关 |
| `appInformation` | object | 录制指定应用，含子字段 `bundleName`:string + `appIndex`:int（choice=true 时附加） |
| `missionId` | int (≥0) | 录制指定窗口（choice=true 时附加） |
| `displayId` | uint64 或 array<uint64> | 录制指定屏幕（choice=true 时附加） |

> `choice` / `checkBoxSelected` / `isInnerAudioBoxSelected` 的 bool 值以**字符串** "true"/"false" 传递，非 JSON bool。

### 录制目标字段解析优先级

choice=true 时按优先级解析录制目标字段确定 CaptureMode：

| 优先级 | 字段 | 解析结果 |
|------|------|---------|
| 1 | `appInformation` | CAPTURE_SPECIFIED_APP |
| 2 | `missionId` | CAPTURE_SPECIFIED_WINDOW |
| 3 | `displayId` | CAPTURE_SPECIFIED_SCREEN |
| — | 均无 | 回退原配置 |

### GetAVScreenCaptureConfigurableParameters（消息码 1）返回约定

返回 JSON 字符串，字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `appPrivacyProtectionSwitch` | bool | 应用隐私保护开关当前值 |
| `systemPrivacyProtectionSwitch` | bool | 系统隐私保护开关当前值 |

## 状态流转

**7 状态状态机**：

| 状态 | 说明 | 允许的操作 |
|------|------|-----------|
| CREATED | 已创建 | Init/配置参数 |
| POPUP_WINDOW | 弹窗中 | 等待用户授权 |
| STARTING | 启动中 | 等待虚拟屏幕/音频/视频就绪 |
| STARTED | 已启动 | StopScreenCapture/PauseScreenCapture |
| PAUSED | 已暂停 | ResumeScreenCapture/StopScreenCapture |
| RESUMED | 已恢复 | StopScreenCapture/PauseScreenCapture |
| STOPPED | 已停止 | Release |

### 状态-能力映射

每个状态对应一组能力位（CAP_INIT/CAP_CONFIG/CAP_ALIVE/CAP_POPUP/CAP_RUNNING/CAP_PAUSED/CAP_ACTIVE），`IsState(cap)` 通过位与判断当前状态是否允许某操作。

### 异常处理路径

| 异常场景 | 处理方式 |
|---------|---------|
| 用户拒绝隐私授权 | 状态回 CREATED，回调 CANCELED |
| 虚拟屏幕创建失败 | 启动失败处理，上报错误 |
| 通话中断 | 通话状态回调，可选 keepCaptureDuringCall 策略 |
| 隐私窗口出现 | 隐私窗口变更 → 虚拟屏幕黑屏处理 |
| 账号切换 | 账号切换回调 → 停止录制并释放资源 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 实例限制 | 全局实例数上限、单 UID 会话数上限、单 UID 数据类型数上限、会话 ID 上限 |
| 业务规则 | 所有操作经过能力位图校验 |
| 性能约束 | 录制操作通过 TaskQueue 异步执行，IPC 线程快速返回不阻塞 |
| 安全与隐私 | 屏幕录制需用户隐私授权弹窗，授权后方可采集 |
| 线程安全 | 互斥锁/读写锁保护状态/配置/ID |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上层依赖 | [ipc-layer-entities](ipc-layer-entities.md) — 通过 IPC 存根/代理接收客户端请求 |
| 下游影响 | [capture-implementation](capture-implementation.md) — 虚拟屏幕/音频采集/文件录制 |
| 平级关联 | ScreenCaptureServer ↔ ListenerManager — 前者实现事件监听接口，后者管理监听器注册 |
| 概念对比 | ScreenCaptureServer vs MonitorServer — 前者管理单个录制实例，后者全局监控 |

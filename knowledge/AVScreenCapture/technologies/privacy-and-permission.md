# 隐私保护与权限机制

> 录屏模块特有的隐私保护体系：权限校验、隐私窗口保护、授权弹窗、内容过滤、Picker 选择器。

## 一、权限体系

### 1.1 权限定义表

| 权限 | 用途 | 授权方式 |
|------|------|---------|
| `ohos.permission.CAPTURE_SCREEN` | 屏幕采集基础权限 | system_grant |
| `ohos.permission.EXEMPT_CAPTURE_SCREEN_AUTHORIZE` | 免授权录屏（系统级白名单） | system_grant |
| `ohos.permission.CUSTOM_SCREEN_RECORDING` | 自定义录屏（跳过弹窗） | system_grant |
| `ohos.permission.TIMEOUT_SCREENOFF_DISABLE_LOCK` | 录屏期间禁锁屏 | system_grant |

### 1.2 权限校验流程

开始录屏前通过 AccessTokenKit 校验 CAPTURE_SCREEN 权限，返回 GRANTED/NOT_GRANTED。

### 1.3 权限使用记录

录屏开始/停止时通过 PrivacyKit 记录权限使用（StartUsingPermission/StopUsingPermission/AddPermissionUsedRecord）。**首实例/末实例机制**：只有同一 PID 的第一个启动实例记录 StartUsingPermission，最后一个停止实例记录 StopUsingPermission，避免多实例重复记录。

## 二、隐私窗口保护

### 2.1 PrivacyProtected 机制

通过两层保护控制虚拟屏幕可见性：

| 保护层 | 作用 |
|--------|-----|
| 系统隐私保护 | 跳过系统级隐私窗口（如密码输入、安全支付） |
| 应用隐私保护 | 跳过特定标签的隐私窗口 |

### 2.2 隐私窗口标签

| 标签 | 含义 | 保护层 |
|------|------|--------|
| `SCB_KEYBOARD_DEFAULT` | 系统键盘（软键盘弹窗） | 系统隐私保护 |
| `TAG_SCREEN_PROTECTION_SENSITIVE_APP` | 敏感应用窗口 | 应用隐私保护 |

当 systemPrivacy 和 appPrivacy 开关一致时同时设置两个标签；不一致时分别设置。

### 2.3 OnPrivateWindowChange 回调

系统检测到隐私窗口出现/消失 → 监听器转发 → Server → 回调应用 ENTER_PRIVATE_SCENE / EXIT_PRIVATE_SCENE，应用可选择停止录屏或继续。

### 2.4 OnPrivacyProtect 回调

通知应用当前系统/应用隐私保护开关状态。

## 三、授权流程

### 3.1 授权判断链路

1. 判断是否需要用户授权：Root 用户(UID=0)免授权，其它需授权
2. 判断免弹窗：EXEMPT 权限 / 系统录屏器 / 自定义录屏权限+Picker未弹出 → 跳过弹窗
3. 需授权 → 弹出授权弹窗（或 Picker）→ 等待用户选择
4. 用户 ALLOW → 继续 OnStartScreenCapture；用户 DENY → 状态回 CREATED，回调 CANCELED

### 3.2 免授权场景

| 场景 | 判断条件 | 说明 |
|------|---------|------|
| Root 用户 | appUid == ROOT_UID(0) | 自动授权 |
| 系统录屏器 | isSystemRecorder | 跳过弹窗 |
| 免授权权限 | EXEMPT_CAPTURE_SCREEN_AUTHORIZE | 系统级白名单 |
| 自定义录屏 | CUSTOM_SCREEN_RECORDING + Picker 未弹出 | 跳过弹窗 |

## 四、光标显示控制

通过虚拟屏幕黑名单控制光标节点可见性：showCursor=true 时光标可见；false 时光标节点被黑名单过滤不可见。

## 五、白名单窗口

白名单与黑名单**可同时生效**：

| 机制 | 含义 |
|------|------|
| 白名单 | 仅白名单内窗口可见，过滤白名单外的其它窗口 |
| 黑名单 | 黑名单内窗口不可见，其余窗口正常显示 |

AddWhiteListWindows 添加窗口到白名单；RemoveWhiteListWindows 从白名单移除窗口。

## 六、内容过滤

| 过滤类型 | 枚举 | 说明 |
|----------|------|------|
| 通知音 | `SCREEN_CAPTURE_NOTIFICATION_AUDIO` | 过滤系统通知声音 |
| 当前应用音 | `SCREEN_CAPTURE_CURRENT_APP_AUDIO` | 过滤录屏应用自身音频 |
| 窗口黑名单 | `windowIDsVec` | 指定窗口在录屏中不可见 |

ExcludeContent 同时更新视频黑名单和音频过滤配置。

## 七、内容变更通知

| 事件 | 枚举值 | 触发场景 |
|------|--------|---------|
| HIDE | SCREEN_CAPTURE_CONTENT_HIDE(0) | 录制窗口进入后台、窗口移出采集屏幕 |
| VISIBLE | SCREEN_CAPTURE_CONTENT_VISIBLE(1) | 录制窗口回到前台、窗口移入采集屏幕 |
| UNAVAILABLE | SCREEN_CAPTURE_CONTENT_UNAVAILABLE(2) | 录制窗口被销毁、采集屏幕断开 |

通过 OnCaptureContentChanged 回调通知应用，携带区域信息。

## 八、Picker 选择器

### 8.1 Picker 模式

| PickerMode | 值 | 说明 |
|------------|---|------|
| WINDOW_ONLY | 0 | 仅窗口 |
| SCREEN_ONLY | 1 | 仅屏幕 |
| SCREEN_AND_WINDOW | 2 | 屏幕和窗口 |
| APP_ONLY | 3 | 仅应用 |
| WINDOW_AND_APP | 4 | 窗口和应用 |
| SCREEN_AND_APP | 5 | 屏幕和应用 |
| SCREEN_WINDOW_AND_APP | 6 | 全部 |

### 8.2 Picker 用户选择流程

PresentPicker 弹出系统 Picker（需 CAP_RUNNING 状态）→ 用户选择窗口/屏幕/应用 → 通过 Controller 上报选择结果 → Server 销毁旧虚拟屏幕、更新采集配置、继续启动 → OnUserSelected 回调。

> Picker 功能受条件编译总开关控制，PC 与手机/平板的参数传递方式不同。
>
> 上报 JSON 字段约定（choice/stopRecording/appInformation/missionId/displayId 等）详见 [service-layer](../entities/service-layer.md) 的 ReportUserChoice 解析与字段约定。

## 九、通话期间保持录屏

| 策略 | keepCaptureDuringCall | 通话时行为 |
|------|----------------------|-----------|
| 默认 | false | 停止录屏，释放实例 |
| 保持 | true | 继续录屏，停止麦克风 |

通话状态变化时，若未启用保持策略则停止录屏；若启用则继续录屏并停止麦克风采集。

## 知识关联

- [capture-lifecycle](capture-lifecycle.md) - 录屏完整生命周期（授权流程集成）
- [ipc-communication](ipc-communication.md) - IPC 通信与回调机制
- [capture-features](capture-features.md) - 录制控制特性
- [design-patterns](design-patterns.md) - 设计模式（Wrapper 模式管理监听器）
- [flows](flows.md) - 关键流程详解（授权弹窗流程、Picker 流程）

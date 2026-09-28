# 录屏完整生命周期

> 从创建到销毁的全流程，包含状态机、能力位图、授权弹窗、数据模式。开发核心参考。

## 一、7 状态状态机

ScreenCaptureServer 采用 7 状态有限状态机管理生命周期，通过能力位图替代 AVPlayer 的状态类继承体系：

```
   Init(config)
   CREATED ─────────────────────→ POPUP_WINDOW
     ↑                                │
     │                  用户拒绝授权  │
     │ ←───────────────────────────── │
     │                                │ 用户允许
     │                                ↓
     │                            STARTING
     │                                │ 启动成功
     │                                ↓
     │            Pause            STARTED ←──┐
     │              │                │       │ Resume
     │              ↓                │       │
     │            PAUSED ←───────────┘       │
     │              │                        │
     │              │ Resume                 │
     │              └──────────────────────→ RESUMED
     │                                        │
     │            StopScreenCapture           │
     └──────────────────────────────────── STOPPED

     POPUP/STARTING/STARTED/PAUSED/RESUMED ──OnError/Stop──→ STOPPED
```

### 状态说明

| 状态 | 含义 | 允许的操作 |
|------|------|-----------|
| CREATED | 初始/配置态 | Init 各配置项、SetCallback、StartScreenCapture |
| POPUP_WINDOW | 授权弹窗等待中 | 等待用户 ALLOW/DENY |
| STARTING | 正在启动采集 | 无（等待启动完成） |
| STARTED | 录屏进行中 | Pause、Stop、Acquire Buffer、SetMicrophoneEnabled 等 |
| PAUSED | 暂停 | Resume、Stop |
| RESUMED | 恢复 | Pause、Stop、Acquire Buffer |
| STOPPED | 已停止 | Release、StartScreenCapture（重新开始） |

### 能力位图机制

每个状态对应一组能力位，IsState(cap) 通过位与判断当前状态是否允许某操作，非法操作返回 MSERR_INVALID_OPERATION。

### 状态-能力映射

| 状态 | 能力位 |
|------|--------|
| CREATED | INIT \| CONFIG \| ALIVE |
| POPUP_WINDOW | ALIVE \| POPUP |
| STARTING | ALIVE |
| STARTED | ALIVE \| RUNNING \| ACTIVE |
| PAUSED | ALIVE \| PAUSED \| ACTIVE |
| RESUMED | ALIVE \| RUNNING \| ACTIVE |
| STOPPED | INIT |

### 状态转换约束（铁律）

1. **必须配置后启动**：CREATED → POPUP_WINDOW → STARTING → STARTED
2. **Pause/Resume 可逆**：STARTED ↔ PAUSED、PAUSED → RESUMED
3. **Stop 回到 STOPPED**：任何 ALIVE 状态 → STOPPED，STOPPED 可重新 StartScreenCapture
4. **Release 不可逆**：Release 后实例销毁
5. **配置只在 CREATED**：SetCaptureMode/SetDataType/Init*/SetRecorderInfo/SetOutputFile 只在 CONFIG 态
6. **Buffer 操作只在 ACTIVE 态**：Acquire/Release Buffer 需要 ACTIVE（STARTED 或 RESUMED）

## 二、完整生命周期流程

### 2.1 创建实例

应用 → Factory 创建 → MediaServiceFactory → IPC → Stub → Server::Create（分配 sessionId、构造 Server、注册到 Manager）→ 返回 Client

### 2.2 初始化配置

应用 → Init(config) → IPC → Server 逐项配置（采集模式/数据类型/音频参数/视频参数/录制信息/输出文件/策略/回调），各方法校验 CONFIG 态，状态保持 CREATED。

### 2.3 启动录屏

应用 → StartScreenCapture → 校验 INIT → PrepareStartCapture（注册监听+参数校验）→ POPUP_WINDOW → 授权流程 → OnStartScreenCapture（STARTING，按数据模式启动）→ PostStartScreenCapture（STARTED，通知 Monitor/应用/注册监听）

### 2.4 暂停 / 恢复

**暂停**：校验 RUNNING + enablePause → FILE 模式暂停 Recorder → 停止镜像/销毁扩展屏 → 停止音频采集 → audioSource Pause → PAUSED → 回调/更新通知栏

**恢复**：校验 PAUSED + enablePause → 通话中且未保持则停止 → 恢复镜像/重建扩展屏 → 同步音频 → audioSource Resume → FILE 模式恢复 Recorder → RESUMED → 回调/更新通知栏

### 2.5 停止录屏

应用 → StopScreenCapture → 若 ALIVE → SetBufferActive(false) → FILE 模式停止 Recorder/原始流停止音视频采集 → PostStop（通知 Monitor Finished、回调状态、移除通知、释放权限状态）→ STOPPED → 注销监听器

### 2.6 释放

应用 → Release → 若 ALIVE 先 Stop → 清理 SA 映射/sessionId → 上报统计 → 移除 ServerMap → 停止 TaskQueue/关闭 fd → 析构

## 三、两种数据模式

| 模式 | DataType | 数据获取方式 | 说明 |
|------|----------|-------------|------|
| 原始流 | ORIGINAL_STREAM | AcquireAudioBuffer/AcquireVideoBuffer | 应用直接获取原始 PCM/YUV 帧 |
| 文件录制 | CAPTURE_FILE | Recorder 引擎编码封装 | 复用 IRecorderService，AudioDataSource 提供混音音频，Surface 提供视频 |

原始流模式中还有 Surface 模式（StartScreenCaptureWithSurface），应用传入自定义 Surface 直接接收视频帧。

## 四、授权流程

1. PrepareStartCapture → 注册账号/通话监听、参数校验
2. 判断免弹窗：Root 用户/系统录屏器/EXEMPT 权限/自定义录屏权限+Picker未弹出 → 跳过弹窗
3. 需授权 → 弹出授权弹窗（或 Picker）→ 等待用户选择
4. 用户 ALLOW → OnStartScreenCapture；用户 DENY → 状态回 CREATED，回调 CANCELED

## 五、回调链路

定义 8 个回调，通过回调代理 → 桥接 → IPC → 应用层：

| 回调 | 触发时机 |
|------|---------|
| OnError | 录屏错误 |
| OnAudioBufferAvailable | 音频缓冲就绪 |
| OnVideoBufferAvailable | 视频缓冲就绪 |
| OnStateChange | 状态变化（STARTED/PAUSED/STOPPED/ENTER_PRIVATE_SCENE 等） |
| OnDisplaySelected | 显示屏选择完成 |
| OnCaptureContentChanged | 采集内容变更（HIDE/VISIBLE/UNAVAILABLE） |
| OnUserSelected | Picker 用户选择完成 |
| OnPrivacyProtect | 隐私保护状态变化 |

## 知识关联

- [ipc-communication](ipc-communication.md) - IPC 通信与回调详解
- [privacy-and-permission](privacy-and-permission.md) - 隐私保护与权限机制
- [capture-features](capture-features.md) - 录制控制特性
- [av-sync-and-buffer](av-sync-and-buffer.md) - 音视频同步与缓冲区管理
- [design-patterns](design-patterns.md) - 设计模式与架构解耦
- [flows](flows.md) - 关键流程详解
- [error-handling-and-dfx](error-handling-and-dfx.md) - 错误处理与 DFX 诊断

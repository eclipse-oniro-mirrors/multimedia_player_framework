# 录制控制特性

> 采集模式、数据模式、音频/视频采集控制、画布、策略配置、水印、暂停恢复等录屏控制特性。

## 一、采集模式

5 种 CaptureMode：

| 模式 | 枚举值 | 说明 | 虚拟屏幕类型 |
|------|--------|------|-------------|
| 主屏幕采集 | CAPTURE_HOME_SCREEN(0) | 采集默认主屏幕 | 镜像 |
| 指定屏幕采集 | CAPTURE_SPECIFIED_SCREEN(1) | 采集指定 displayId 屏幕 | 镜像 |
| 指定窗口采集 | CAPTURE_SPECIFIED_WINDOW(2) | 采集指定 missionId 窗口 | 镜像 + 白名单/黑名单 |
| 虚拟扩展屏采集 | CAPTURE_VIRTUAL_EXTENDED_SCREEN(3) | 采集虚拟扩展屏幕 | 扩展 |
| 指定应用采集 | CAPTURE_SPECIFIED_APP(4) | 采集指定应用窗口 | 镜像 + 白名单 |

镜像模式通过 MakeMirror 实现；扩展模式通过 MakeVirtualScreenExtended 实现。

## 二、数据模式

| 模式 | DataType | 数据模式枚举 | 说明 |
|------|----------|-------------|------|
| 原始流 | ORIGINAL_STREAM(0) | BUFFER_MODE / SURFACE_MODE | 应用通过 AcquireBuffer 获取原始数据 |
| 文件录制 | CAPTURE_FILE(2) | FILE_MODE | Recorder 引擎编码封装为媒体文件 |

### 2.1 原始流模式

- **BUFFER_MODE**：应用通过 AcquireVideoBuffer/ReleaseVideoBuffer 主动获取/释放视频帧
- **SURFACE_MODE**：应用通过 StartScreenCaptureWithSurface 传入自定义 Surface，直接接收视频帧

### 2.2 文件录制模式

复用 IRecorderService 引擎，AudioDataSource 提供混音音频，虚拟屏幕 Surface 提供视频。

## 三、音频采集控制

### 3.1 AudioCaptureSourceType

| 类型 | 枚举值 | 说明 |
|------|--------|------|
| SOURCE_DEFAULT | 0 | 默认音频源 |
| MIC | 1 | 麦克风 |
| ALL_PLAYBACK | 2 | 内录（所有播放音） |
| APP_PLAYBACK | 3 | 应用播放音 |

### 3.2 SetMicrophoneEnabled

| 场景 | 行为 |
|------|------|
| 启动前（非 RUNNING） | 仅设置标志，启动时生效 |
| 运行中（RUNNING） | 立即启停麦克风采集 |
| 通话期间 | 麦克风不可用 → OnStateChange(MIC_UNAVAILABLE) |

### 3.3 VoIP 通话期间音频处理

设置 VoIP 通话状态影响音频采集策略，按通话状态计算麦克风/内录的启停。

### 3.4 音频内容过滤

支持过滤通知音、当前应用音。

## 四、视频采集控制

### 4.1 虚拟屏幕创建

| 方法 | 说明 |
|------|------|
| CreateVirtualScreen(consumer) | 创建虚拟屏幕并设置镜像/扩展 |
| MakeVirtualScreenMirror | 镜像模式 |
| MakeVirtualScreenExtended | 扩展模式 |
| DestroyVirtualScreen | 销毁虚拟屏幕 |

### 4.2 SetMaxVideoFrameRate

帧率范围 1~60，通过虚拟屏幕最大刷新率控制。

### 4.3 ResizeCanvas

调整虚拟屏幕尺寸，仅 ORIGINAL_STREAM 模式可用。

### 4.4 旋转控制

| 方法 | 说明 |
|------|------|
| SetCanvasRotation(bool) | 手动设置画布旋转（0°/90°） |
| SetContentAutoRotation(bool) | 内容跟随屏幕旋转（仅 CREATED 设置） |

### 4.5 ShowCursor

通过虚拟屏幕黑名单过滤光标节点。

### 4.6 SetCaptureArea

区域采集：重新设置镜像区域。

### 4.7 SetCaptureAreaHighlight

| 配置项 | 范围 | 说明 |
|--------|------|------|
| lineThickness | 1~8 | 描边线宽 |
| lineColor | 0x00000000~0xFFFFFFFF | ARGB 颜色 |
| mode | HIGHLIGHT_MODE_CLOSED / CORNER_WRAP | 描边样式 |

仅 CAPTURE_SPECIFIED_WINDOW 模式有效。

### 4.8 UpdateSurface

更新虚拟屏幕的消费者 Surface，仅 Surface 模式。

### 4.9 GetMultiDisplayCaptureCapability

查询多屏采集能力。

## 五、画布与填充模式

| FillMode | 值 | 说明 |
|----------|---|------|
| PRESERVE_ASPECT_RATIO | 0 | 保持宽高比 |
| SCALE_TO_FILL | 1 | 拉伸填充 |

## 六、策略配置

| 策略项 | 默认值 | 生效阶段 |
|--------|--------|---------|
| enableDeviceLevelCapture | false | 创建虚拟屏幕时 |
| keepCaptureDuringCall | false | 通话事件触发时 |
| strategyForPrivacyMaskMode | 0 | 创建虚拟屏幕时 |
| canvasFollowRotation | false | 屏幕旋转 |
| enableBFrame | false | Recorder 编码配置 |
| pickerPopUp | -1 | 授权弹窗判断 |
| fillMode | 0 | 虚拟屏幕缩放 |
| enablePause | false | Pause/Resume 校验 |

SetScreenCaptureStrategy 仅在 POPUP_WINDOW 之前允许设置。

## 七、水印

| 约束 | 说明 |
|------|------|
| 状态 | 仅 CREATED 态允许 |
| 数据模式 | 仅 CAPTURE_FILE |
| 底层 | Recorder 引擎 AddWatermark |

## 八、暂停 / 恢复

| 操作 | 前置条件 | 执行内容 |
|------|---------|---------|
| PauseScreenCapture | RUNNING + enablePause | PauseRecorder + PauseVideoCapture + StopAudioCapture |
| ResumeScreenCapture | PAUSED + enablePause | ResumeVideoCapture + SyncAudioCaptures + ResumeRecorder |

## 九、媒体描述查询

GetAVScreenCaptureConfigurableParameters 通过 Controller IPC 查询当前可配置参数，返回 JSON 格式参数描述。

## 知识关联

- [capture-lifecycle](capture-lifecycle.md) - 录屏完整生命周期
- [av-sync-and-buffer](av-sync-and-buffer.md) - 音视频同步与缓冲区管理
- [privacy-and-permission](privacy-and-permission.md) - 隐私保护与权限机制
- [flows](flows.md) - 关键流程详解

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

镜像模式通过 `MakeVirtualScreenMirror` → `ScreenManager::MakeMirror` 实现；扩展模式通过 `MakeVirtualScreenExtended` 实现。

## 二、数据模式

| 模式 | DataType | 数据模式枚举 | 说明 |
|------|----------|-------------|------|
| 原始流 | ORIGINAL_STREAM(0) | BUFFER_MODE / SUFFACE_MODE | 应用通过 AcquireAudioBuffer/AcquireVideoBuffer 获取原始数据 |
| 文件录制 | CAPTURE_FILE(2) | FILE_MODE | Recorder 引擎编码封装为媒体文件 |

### 2.1 原始流模式

- **BUFFER_MODE**：应用通过 `AcquireVideoBuffer` / `ReleaseVideoBuffer` 主动获取/释放视频帧
- **SUFFACE_MODE**：应用通过 `StartScreenCaptureWithSurface(surface)` 传入自定义 Surface，直接接收视频帧

### 2.2 文件录制模式

复用 `IRecorderService` 引擎，AudioDataSource 提供混音音频，虚拟屏幕 Surface 提供视频：

```
StartScreenCaptureFile
  → InitRecorder() → providers_->CreateRecorder()
  → SyncAudioCaptures() → AudioCapturerWrapper 启动
  → recorder_->Start()
  → CreateVirtualScreen(consumer_) → 虚拟屏幕提供视频帧
```

## 三、音频采集控制

### 3.1 AudioCaptureSourceType

| 类型 | 枚举值 | 说明 |
|------|--------|------|
| SOURCE_DEFAULT | 0 | 默认音频源 |
| MIC | 1 | 麦克风 |
| ALL_PLAYBACK | 2 | 内录（所有播放音） |
| APP_PLAYBACK | 3 | 应用播放音 |

### 3.2 SetMicrophoneEnabled

```cpp
int32_t SetMicrophoneEnabled(bool isMicrophone);
```

| 场景 | 行为 |
|------|------|
| 启动前（非 CAP_RUNNING） | 仅设置 `isMicrophoneSwitchTurnOn_` 标志，启动时生效 |
| 运行中（CAP_RUNNING） | `SyncAudioCaptures()` 立即启停麦克风采集 |
| 通话期间 | 麦克风不可用 → `OnStateChange(MIC_UNAVAILABLE)` |

### 3.3 VoIP 通话期间音频处理

`SetIsInVoIPCall` 设置 VoIP 通话状态，影响音频采集策略：

```
CalcAudioCaptureSyncFlags(state)：
  - micStop = !isMicrophoneSwitchTurnOn || (state & AUDIO_STATE_TEL) ||
              (micAudioCapture_->IsInVoIPCall() != ((state & AUDIO_STATE_VOIP) != 0))
  - micStart = isMicrophoneSwitchTurnOn && !(state & AUDIO_STATE_TEL)
  - innerStart = isOriginalStream || (isMixMode && (state != 0 || micStop))
  - innerStop = !isOriginalStream && isMixMode && state == 0 && !micStop
```

### 3.4 音频内容过滤

`UpdateAudioCapturerConfig(filter)` 更新 AudioCapturer 的音频过滤配置，支持通知音/当前应用音过滤。

## 四、视频采集控制

### 4.1 虚拟屏幕创建

| 方法 | 说明 |
|------|------|
| `CreateVirtualScreen(consumer)` | 创建虚拟屏幕并设置镜像/扩展 |
| `MakeVirtualScreenMirror()` | 镜像模式：`ScreenManager::MakeMirror` |
| `MakeVirtualScreenExtended()` | 扩展模式：创建扩展虚拟屏幕 |
| `DestroyVirtualScreen()` | 销毁虚拟屏幕 |

### 4.2 SetMaxVideoFrameRate

```cpp
int32_t SetMaxVideoFrameRate(int32_t frameRate);  // 1~60
```

通过 `SetVirtualScreenMaxRefreshRate` 控制虚拟屏幕最大刷新率。

### 4.3 ResizeCanvas

```cpp
int32_t ResizeCanvas(int32_t width, int32_t height);
```

通过 `ResizeVirtualScreen` 调整虚拟屏幕尺寸，仅 `ORIGINAL_STREAM` 模式可用。

### 4.4 旋转控制

| 方法 | 说明 |
|------|------|
| `SetCanvasRotation(bool)` | 手动设置画布旋转（0°/90°） |
| `SetContentAutoRotation(bool)` | 内容跟随屏幕旋转（仅在 CREATED 设置） |

底层调用 `SetVirtualMirrorScreenCanvasRotation`。

### 4.5 ShowCursor

通过 `SetVirtualScreenBlackList` 过滤光标节点类型 SurfaceNode。

### 4.6 SetCaptureArea

```cpp
int32_t SetCaptureArea(uint64_t displayId, OHOS::Rect area);
```

区域采集：通过 `GetScreenAreaOfDisplayArea` + `MakeMirror` 重新设置镜像区域。

### 4.7 SetCaptureAreaHighlight

```cpp
int32_t SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config);
```

| 配置项 | 范围 | 说明 |
|--------|------|------|
| lineThickness | 1~8 | 描边线宽 |
| lineColor | 0x00000000~0xFFFFFFFF | ARGB 颜色 |
| mode | HIGHLIGHT_MODE_CLOSED / CORNER_WRAP | 描边样式 |

仅 `CAPTURE_SPECIFIED_WINDOW` 模式有效，通过 `WindowManager::UpdateOutline` 设置窗口描边。

### 4.8 UpdateSurface

```cpp
int32_t UpdateSurface(sptr<Surface> surface);  // 仅 Surface 模式
```

通过 `SetVirtualScreenSurface` 更新虚拟屏幕的消费者 Surface。

### 4.9 MultiDisplayCapability

```cpp
int32_t GetMultiDisplayCaptureCapability(const std::vector<uint64_t> &displayIds,
    MultiDisplayCapability &capability);
```

通过 `QueryMultiScreenCapture` 查询多屏采集能力。

## 五、画布与填充模式

```cpp
enum AVScreenCaptureFillMode {
    PRESERVE_ASPECT_RATIO = 0,  // 保持宽高比
    SCALE_TO_FILL = 1,          // 拉伸填充
};
```

通过 `SetVirtualMirrorScreenScaleMode` 设置虚拟屏幕缩放模式：

| FillMode | ScreenScaleMode |
|----------|-----------------|
| PRESERVE_ASPECT_RATIO | UNISCALE_MODE |
| SCALE_TO_FILL | FILL_MODE |

## 六、策略配置

```cpp
struct ScreenCaptureStrategy {
    bool enableDeviceLevelCapture = false;      // 设备级录制
    bool keepCaptureDuringCall = false;         // 通话期间保持
    int32_t strategyForPrivacyMaskMode = 0;      // 隐私遮罩模式
    bool canvasFollowRotation = false;           // 画布跟随旋转
    bool enableBFrame = false;                   // B 帧编码
    bool setByUser = false;                      // 用户设置标志
    AVScreenCapturePickerPopUp pickerPopUp;      // Picker 弹出策略
    AVScreenCaptureFillMode fillMode;            // 填充模式
    bool enablePause = false;                    // 暂停功能
};
```

`SetScreenCaptureStrategy` 仅在 `captureState_ < POPUP_WINDOW` 时允许设置。

| 策略项 | 生效阶段 |
|--------|---------|
| enableDeviceLevelCapture | 创建虚拟屏幕时（VirtualScreenOption.flags_） |
| keepCaptureDuringCall | 通话事件触发时 |
| strategyForPrivacyMaskMode | 创建虚拟屏幕时（flags_） |
| canvasFollowRotation | `SetVirtualScreenAutoRotation` |
| enableBFrame | Recorder 编码配置 |
| pickerPopUp | StartAuthWindow 时判断 |
| fillMode | `SetVirtualMirrorScreenScaleMode` |
| enablePause | PauseScreenCapture/ResumeScreenCapture 校验 |

## 七、水印

```cpp
int32_t AddWatermark(std::shared_ptr<AVBuffer> &watermarkBuffer, int32_t width,
    int32_t height, int32_t &watermarkCount);
```

| 约束 | 说明 |
|------|------|
| 状态 | 仅 CREATED 态允许 |
| 数据模式 | 仅 CAPTURE_FILE |
| 底层 | `recorder_->AddWatermark()` |

## 八、暂停 / 恢复

| 操作 | 前置条件 | 执行内容 |
|------|---------|---------|
| PauseScreenCapture | CAP_RUNNING + enablePause | PauseRecorder + PauseVideoCapture + StopAudioCapture |
| ResumeScreenCapture | CAP_PAUSED + enablePause | ResumeVideoCapture + SyncAudioCaptures + ResumeRecorder |

## 九、媒体描述查询

`GetAVScreenCaptureConfigurableParameters` 通过 Controller IPC 查询当前可配置参数，返回 JSON 格式参数描述。

## 知识关联

- [[capture-lifecycle]] - 录屏完整生命周期
- [[av-sync-and-buffer]] - 音视频同步与缓冲区管理
- [[privacy-and-permission]] - 隐私保护与权限机制
- [[flows]] - 关键流程详解

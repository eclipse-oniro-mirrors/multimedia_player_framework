# 模块演进

> 屏幕录制引擎、ScreenCaptureServer 模块、IPC 通信、隐私保护的版本演进记录。

## 一、屏幕录制引擎演进

| 维度 | 说明 |
|------|------|
| 引入版本 | API 10（OH_AVScreenCapture C API） |
| 架构特点 | 无独立引擎层，ScreenCaptureServer 直接调用 Rosen（显示管理）和 AudioCapturer（音频采集），不同于 AVPlayer 的 EngineFactory + Pipeline 架构 |
| API 12+ | 新增 Strategy 策略配置、Picker 选择器、ContentFilter 内容过滤、Highlight 高亮区域、多屏采集、Pause/Resume、Watermark 等高级特性 |
| 数据模式 | BUFFER_MODE（原始帧缓冲）→ SUFFACE_MODE（Surface 直接传递）→ FILE_MODE（Recorder 编码封装） |
| 废弃 | ENCODED_STREAM 数据类型不支持（返回 MSERR_UNSUPPORT） |

## 二、ScreenCaptureServer 模块演进

| 阶段 | 变更内容 |
|------|---------|
| 1. 初始版本 | 基础录屏服务端、7 状态能力位图状态机、IPC Stub/Proxy、CAPTURE_HOME_SCREEN/指定窗口模式 |
| 2. 数据模式扩展 | ORIGINAL_STREAM 原始流模式 + CAPTURE_FILE 文件录制模式、Surface 模式（StartScreenCaptureWithSurface） |
| 3. 隐私保护机制 | PrivacyProtected 系统级/应用级隐私窗口保护、OnPrivateWindowChange 回调、OnPrivacyProtect 回调、隐私窗口标签（SCB_KEYBOARD_DEFAULT/TAG_SCREEN_PROTECTION_SENSITIVE_APP） |
| 4. Picker 选择器 | PresentPicker 弹出系统选择器、条件编译 SUPPORT_SCREEN_CAPTURE_PICKER/PC_STANDARD/SUPPORT_PICKER_PHONE_PAD、PickerMode 多模式选择、ExcludePickerWindows |
| 5. 多屏支持 | CAPTURE_VIRTUAL_EXTENDED_SCREEN 扩展屏模式、GetMultiDisplayCaptureCapability 多屏能力查询、SetCaptureArea 区域采集、OnRecordDisplayChange/OnScreenConnect/OnScreenDisconnect 监听 |
| 6. 通话期间保持 | StrategyForKeepCaptureDuringCall 策略、条件编译 SUPPORT_CALL、InCallObserver 通话状态监听、TelCallStateUpdated |
| 7. 暂停/恢复 | PauseScreenCapture/ResumeScreenCapture、enablePause 策略开关、通知栏实时视图 PAUSE/RESUME 按钮 |
| 8. 内容过滤 | ExcludeContent 内容过滤（filteredAudioContents 通知音/当前应用音 + windowIDsVec 窗口黑名单）、UpdateAudioCapturerConfig 音频过滤 |
| 9. 内容变更通知 | OnCaptureContentChanged 回调、HIDE/VISIBLE/UNAVAILABLE 事件、窗口生命周期监听 |
| 10. 高级特性 | SetCaptureAreaHighlight 窗口描边高亮、AddWatermark 水印、SetScreenCaptureStrategy 策略配置、SetCanvasRotation/SetContentAutoRotation 旋转控制 |
| 11. 账户与语言 | OnAccountSwitched 账户切换停止录屏、OnLanguageSwitch 语言切换刷新通知、LF_ACCOUNT/LF_LANG_SWITCH 监听标志 |

## 三、IPC 通信演进

| 阶段 | 变更内容 |
|------|---------|
| 1. 初始版本 | 基础 IPC Stub/Proxy：IStandardScreenCaptureService（SetCaptureMode/Start/Stop/Acquire/Release）、IStandardScreenCaptureListener（OnError/OnAudioAvailable/OnVideoAvailable/OnStateChange） |
| 2. Listener 增强 | 新增 OnDisplaySelected（显示屏选择）、OnCaptureContentChanged（内容变更）、OnUserSelected（用户选择）、OnPrivacyProtect（隐私保护）共 8 个回调 |
| 3. Controller IPC | 新增 IStandardScreenCaptureController（ReportAVScreenCaptureUserChoice/GetAVScreenCaptureConfigurableParameters/Destroy），Picker 用户选择通过 Controller 分发 |
| 4. Monitor IPC | 新增 IStandardScreenCaptureMonitorService（IsScreenCaptureWorking/IsSystemScreenRecorder/IsSystemScreenRecorderWorking）、IStandardScreenCaptureMonitorListener（OnScreenCaptureStarted/OnScreenCaptureFinished/OnScreenCaptureDied） |
| 5. 服务接口扩展 | 从基础采集控制扩展到 41 个消息码，新增 Strategy/Picker/Highlight/Watermark/Pause/Resume/MultiDisplay 等接口 |
| 6. 异常恢复 | DeathRecipient 服务端/客户端死亡检测、SceneSessionManager 死亡监听、NotificationSubscriber 通知栏按钮响应 |

## 四、隐私保护演进

| 阶段 | 变更内容 |
|------|---------|
| 1. 基础权限校验 | CheckScreenCapturePermission → AccessTokenKit::VerifyAccessToken(CAPTURE_SCREEN) |
| 2. 授权弹窗 | RequestUserPrivacyAuthority → StartAuthWindow → UIExtensionAbilityConnection 弹窗、OnReceiveUserPrivacyAuthority 接收用户选择 |
| 3. 免授权权限 | EXEMPT_CAPTURE_SCREEN_AUTHORIZE 权限 → CheckPrivacyWindowSkipPermission 免弹窗、Root 用户 UID=0 自动授权 |
| 4. 自定义录屏 | CUSTOM_SCREEN_RECORDING 权限 → CheckCustScrRecPermission → IsSkipPrivacyWindow 跳过弹窗 |
| 5. 隐私窗口保护 | PrivacyProtected（SetScreenSkipProtectedWindow + SetScreenPrivacyWindowTagSwitch）、系统隐私保护 vs 应用隐私保护、OnPrivateWindowChange → ENTER_PRIVATE_SCENE/EXIT_PRIVATE_SCENE |
| 6. Picker 用户选择 | PresentPicker 弹出系统选择器、ReportAVScreenCaptureUserChoice 上报选择、OnUserSelected 回调 |
| 7. 内容过滤 | ExcludeContent 过滤通知音/当前应用音/窗口黑名单、UpdateAudioCapturerConfig 动态更新音频过滤 |
| 8. 内容变更通知 | OnCaptureContentChanged 回调、HIDE/VISIBLE/UNAVAILABLE 事件 |
| 9. 权限使用记录 | PrivacyKit StartUsingPermission/StopUsingPermission/AddPermissionUsedRecord、首实例/末实例机制避免重复记录 |

## 知识关联

- [[design-patterns]] - 设计模式与架构解耦
- [[capture-lifecycle]] - 录屏完整生命周期
- [[ipc-communication]] - IPC 通信与回调机制
- [[privacy-and-permission]] - 隐私保护与权限机制

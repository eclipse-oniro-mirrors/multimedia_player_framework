# 关键流程详解

> 录屏初始化、授权弹窗、虚拟屏幕创建、音频采集、视频缓冲、文件录制、暂停恢复、停止释放、隐私窗口、Picker、实例限制、Monitor 通知、通知栏控制等核心流程。

## 一、录屏初始化与启动流程

1. 创建实例：应用 → Factory → MediaServiceFactory → IPC → Stub → Server::Create（分配 sessionId、构造 Server、注册到 Manager）→ 返回 Client
2. Init 配置：SetCaptureMode/SetDataType/InitAudioCap/InitVideoCap/SetRecorderInfo/SetOutputFile，校验 CONFIG，写入配置，状态保持 CREATED
3. StartScreenCapture：校验 INIT → PrepareStartCapture（注册监听+参数校验）→ POPUP_WINDOW → 授权流程 → OnStartScreenCapture → PostStartScreenCapture → STARTED

**异常分支**：sessionId 超限→null 实例；参数校验失败→对应错误码；通话中→MSERR_UNSUPPORT_INCALL+STOPPED_BY_CALL；Display 获取失败→MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN。

## 二、授权弹窗流程

1. PrepareStartCapture → 注册账号/通话监听、参数校验
2. 判断免弹窗：EXEMPT 权限/系统录屏器/Root/自定义录屏+Picker未弹出
3. 判断是否需授权：Root 免授权，其它需授权
4. 需授权 → StartAuthWindow（Picker 或隐私弹窗）→ 等待用户选择
5. 用户 ALLOW → OnStartScreenCapture；DENY → 状态回 CREATED，回调 CANCELED

**异常分支**：EXEMPT 未授予→正常授权流程；弹窗失败→STOPPED+REQUEST_USER_PRIVACY_AUTHORITY_FAILED；弹窗期间状态非法→OnError+Stop；DENY→CREATED+CANCELED。

## 三、虚拟屏幕创建流程

1. OnStartScreenCapture → STARTING → 按数据模式启动（ORIGINAL_STREAM/CAPTURE_FILE）
2. CreateVirtualScreen → 构建 VirtualScreenOption → 创建虚拟屏幕 → 设置旋转/隐私保护/光标
3. PrepareVirtualScreenMirror → 设置缩放/黑名单 → MakeMirror（镜像）或 MakeVirtualScreenExtended（扩展）

**异常分支**：CreateVirtualScreen 失败→MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN；MakeMirror 失败→销毁+MSERR_UNKNOWN_MAKE_MIRROR；屏幕断开→UNAVAILABLE 回调。

## 四、音频采集启动流程

1. SyncAudioCaptures → 计算启停标志
2. StartInnerAudioCapture → 创建 Wrapper → 启动 AudioCapturer → 注册到 audioSource
3. StartMicAudioCapture → 创建 Wrapper → 启动 → 注册到 audioSource
4. 数据回调 → OnReadData → CacheBuffer 入队 → 通知缓冲就绪

**异常分支**：内录创建失败→返回错误码，不影响视频；麦克风启动失败→MIC_UNAVAILABLE 回调（可配置忽略不阻断）；通话期间→停麦+MIC_UNAVAILABLE。

## 五、视频缓冲获取流程

1. 虚拟屏幕渲染帧 → Producer 写入 → Consumer 收到 OnBufferAvailable
2. 消息队列 push GET_BUFFER → 独立线程取出（超限丢旧消息）
3. OnBufferAvailableAction → AcquireBuffer → fence 等待 → 缓存失效 → 队列满则丢帧 → 入队 → 回调应用
4. 应用 AcquireVideoBuffer（等待非空，超时 1s）→ 取队首
5. 应用 ReleaseVideoBuffer → 归还 Consumer → 弹出

**异常分支**：AcquireBuffer 失败→丢帧；队列满→丢帧；AcquireVideoBuffer 超时→MSERR_UNKNOWN；缓冲线程未启动→MSERR_NO_MEMORY。

## 六、文件录制流程

1. StartScreenCaptureFile → InitRecorder（创建 Recorder、配置编码/格式/输出、创建 audioSource）
2. SyncAudioCaptures → 启动内录/麦克风
3. recorder_->Start
4. CreateVirtualScreen → 虚拟屏幕提供视频帧给 Recorder
5. AudioDataSource::ReadAt → 按混音模式取数据 → A/V 同步对齐 → 混音/透传 → 写入 AVBuffer

**异常分支**：InitRecorder 失败→MSERR_UNKNOWN_CREAT_RECORDER+守卫清理；Recorder 启动失败→守卫 Release；无数据→SKIP_WITHOUT_LOG；同步失败→填充静音帧。

## 七、暂停 / 恢复流程

**暂停**：校验 RUNNING+enablePause → FILE 模式 PauseRecorder → PauseVideoCapture（扩展屏销毁/其它停止镜像）→ StopAudioCapture → audioSource Pause → PAUSED → 回调/通知栏

**恢复**：校验 PAUSED+enablePause → 通话中且未保持则停止 → ResumeVideoCapture（扩展屏重建/其它恢复镜像）→ SyncAudioCaptures → audioSource Resume → FILE 模式 ResumeRecorder → RESUMED → 回调/通知栏

**异常分支**：PauseRecorder/PauseVideoCapture/ResumeVideoCapture/SyncAudioCaptures 失败→StopCaptureOnError；恢复时通话→STOPPED_BY_CALL+Release。

## 八、停止与释放流程

**停止**：StopScreenCapture → 若 ALIVE → SetBufferActive(false) → FILE 模式停 Recorder/原始流停音视频 → PostStop（通知 Monitor Finished、回调状态、移除通知、释放权限）→ STOPPED → 注销监听器

**释放**：Release → 若 ALIVE 先 Stop → 清理 SA 映射/sessionId → 上报统计 → 移除 ServerMap → 停止 TaskQueue/关闭 fd → 析构

**异常分支**：重复 Stop→幂等返回 OK；Recorder Stop 失败→继续清理；虚拟屏幕销毁失败→跳过；未先停就 Release→自动 Stop。

## 九、隐私窗口处理流程

1. 系统检测隐私窗口变化 → 监听器转发
2. Server::OnPrivateWindowChange → 异步入队 → 回调 ENTER_PRIVATE_SCENE/EXIT_PRIVATE_SCENE
3. 应用响应（停止或继续）
4. 保护开关变化 → OnPrivacyProtect 回调

## 十、Picker 用户选择流程

1. PresentPicker → 校验 RUNNING → 弹出系统 Picker
2. 用户选择 → 通过 Controller 上报 → Server 解析 → 销毁旧虚拟屏幕 → 更新配置 → OnReceiveUserPrivacyAuthority(true) → OnStartScreenCapture
3. OnUserSelected 回调选择信息

**异常分支**：非 RUNNING→MSERR_INVALID_OPERATION；Picker 不支持→MSERR_UNKNOWN_UNSUPPORT；用户取消→销毁+停止；配置无效→回退。

> 上报 JSON 字段约定详见 [service-layer](../entities/service-layer.md) 的 ReportUserChoice 解析与字段约定。

## 十一、实例数量限制流程

1. CanScreenCaptureInstanceBeCreate → 检查全局实例数/单 UID 会话数/单 UID 同 DataType 数
2. SetAndCheckLimit → 创建前检查计数
3. SetAndCheckSaLimit → SA-UID 映射校验 + 检查计数 + 注册映射

**异常分支**：全局/单 UID 超限→MSERR_INVALID_OPERATION；SA-UID 已存在→MSERR_INVALID_OPERATION。

## 十二、Monitor 通知流程

1. 录屏启动成功 → 通知 Monitor.CallOnScreenCaptureStarted(pid) → 遍历监听器 → IPC → 应用层 OnScreenCaptureStarted(pid)
2. 录屏停止 → CallOnScreenCaptureFinished(pid) → 通知监听器
3. 录屏服务死亡 → MonitorServer DeathRecipient → OnScreenCaptureDied

## 十三、通知栏控制流程

1. 创建通知：SubscribeLocalLiveView + InitLiveViewContent + SetupPublishRequest + PublishNotification
2. 按钮响应：OnResponse(notificationId, button) → 定位 Server → stop/pause/resume/mic
3. 更新通知：UpdateLiveViewContent + 重新发布
4. 移除通知：CancelNotification

**异常分支**：通知发布失败→停止录屏；实例不存在→忽略按钮；语言切换→刷新通知文本。

## 知识关联

- [capture-lifecycle](capture-lifecycle.md) - 录屏完整生命周期
- [ipc-communication](ipc-communication.md) - IPC 通信与回调机制
- [privacy-and-permission](privacy-and-permission.md) - 隐私保护与权限机制
- [av-sync-and-buffer](av-sync-and-buffer.md) - 音视频同步与缓冲区管理
- [error-handling-and-dfx](error-handling-and-dfx.md) - 错误处理与 DFX 诊断

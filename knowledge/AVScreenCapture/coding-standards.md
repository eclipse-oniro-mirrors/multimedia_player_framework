# 编码铁律

## 通用编码铁律

> 描述通用编码规范，必须简洁明了，采用反模式方式描述

- **禁止**跨 IPC 边界直接调用另一进程对象，**采用** IPC Proxy/Stub + MessageParcel 序列化通信
- **禁止**为录屏单独引入引擎选择层或 Pipeline，**采用**直接调用 Rosen VirtualScreen + AudioCapturer + Recorder 引擎（通过 ScreenCaptureServiceProviders 注入）
- **禁止**绕过能力位图状态机直接执行录屏操作，**采用** `IsState(CAP_xxx)` 校验，非法状态返回 MSERR_INVALID_OPERATION
- **禁止**跳过权限校验或隐私授权流程直接开始录屏，**采用** StartScreenCapture 前校验 CAPTURE_SCREEN 权限 + 隐私授权（弹窗或 EXEMPT 权限）
- **禁止**虚拟屏幕创建后不配对销毁，**采用** CreateVirtualScreen 与 DestroyVirtualScreen 严格配对，Stop/Release/异常路径均执行销毁
- **禁止** AudioCapturer 创建后不配对 Stop/Release，**采用** AudioCapturerWrapper 析构时 Stop + Release AudioCapturer，确保音频设备释放
- **禁止**回调指针无锁保护跨线程访问，**采用** shared_mutex/shared_lock 保护 cbProxy_、shared_ptr 回调的读写
- **禁止** SurfaceBuffer Acquire 后不 Release，**采用** AcquireVideoBuffer/AcquireAudioBuffer 与 ReleaseVideoBuffer/ReleaseAudioBuffer 严格配对
- **禁止**监听器注册后不注销，**采用** RegisterListeners(flags) 与 UnregisterListeners(LF_ALL) 配对，Server 释放时统一注销
- **禁止**通知栏发布后不移除，**采用** 录屏开始发布通知、结束/异常时移除，notificationId 生命周期与录屏会话一致
- **禁止**麦克风/内录音频缓冲无限积压，**采用** CacheBuffer 预分配 + 容量上限，满时丢弃旧帧
- **禁止**超限创建录屏实例（全局 >4 或单 UID >4），**采用** SetAndCheckLimit/SetAndCheckSaLimit 创建前检查计数
- **禁止**使用缩写或歧义命名，**采用**完整语义化命名（ScreenCaptureServer 非 SCS，AudioCapturerWrapper 非 ACW）
- **禁止**成员变量与局部变量同名，**采用** trailing_ 后缀标注（captureState_、virtualScreenId_、consumer_）
- **禁止**裸指针跨模块传递，**采用** unique_ptr（唯一所有权）或 shared_ptr + weak_ptr（共享所有权打破循环）
- **禁止** C 风格强制类型转换，**采用** static_cast / dynamic_cast / reinterpret_cast 并注明理由
- **禁止**公共头文件与内部实现混放，**采用** InnerAPI 头文件放 interfaces/inner_api/，与 services/ 和 frameworks/ 严格分离
- **禁止**多线程访问共享状态不加锁，**采用**互斥锁或原子变量保护（captureConfigMutex_、mutex_、audioMutex_、captureIdsMutex_）
- **禁止**持锁状态下调用外部模块未知接口，**采用**锁内只操作本模块数据，跨模块调用释放锁后执行
- **禁止**回调线程执行长时间阻塞操作，**采用**异步投递耗时处理
- **禁止** IPC OnRemoteRequest 中执行耗时操作，**采用**参数校验 + 任务分发至工作线程
- **禁止** IPC 回调链路同步等待客户端响应，**采用**异步投递

## 其它编码铁律

> 描述安全、内存、性能等编码规范要求

- **禁止**公开 API 跳过权限校验，**采用**所有入口执行权限验证，系统敏感接口校验调用者身份
- **禁止** IPC 反序列化跳过参数校验，**采用**校验必要字段存在性 + 取值范围合法性（CaptureMode/DataType 枚举边界）
- **禁止**虚拟屏幕 screenId 未校验直接使用，**采用** CreateVirtualScreen 返回值校验，无效 ID 返回错误
- **禁止**音频采集 sourceType 非法值直接传入 AudioCapturer，**采用**枚举边界校验（SOURCE_INVALID 拒绝）
- **禁止**隐私窗口保护遗漏系统级或应用级，**采用** PrivacyProtected 同时设置 systemPrivacyProtection 和 appPrivacyProtection
- **禁止** SurfaceBuffer 跨 IPC 传递裸指针，**采用** Surface/BufferStack 序列化或文件描述符传递
- **禁止**动态库加载后不调用 dlclose 释放，**采用**引用计数归零后卸载
- **禁止** shared_ptr 循环引用不配合 weak_ptr，**采用** Callback 与 Server 间使用 weak_ptr 打破循环
- **禁止**音频混音热路径分配堆内存，**采用** CacheBuffer 预分配，严禁每帧 new/malloc
- **禁止**视频帧路径冗余数据拷贝，**采用** SurfaceBuffer sptr 引用传递零拷贝
- **禁止** Stop 操作阻塞 UI 线程，**采用**异步执行 + 资源释放
- **禁止** Surface/虚拟屏幕/AudioCapturer 等系统资源不释放，**采用**录屏销毁时 DestroyVirtualScreen + StopBufferThread + Release AudioCapturer + 注销死亡通知
- **禁止** GN 构建遗漏 CFI 安全编译标志，**采用**共享库启用 CFI 强化
- **禁止** versionscript 遗漏导出符号声明，**采用**导出符号明确声明（CreateScreenCaptureServer 等 4 个），未声明符号隐藏
- **禁止**通话中断策略硬编码，**采用** ScreenCaptureStrategy.keepCaptureDuringCall 可配置
- **禁止** Picker 用户选择结果未经校验直接应用，**采用** Controller 上报 choice 后校验合法性再配置录屏目标

## Agent 常见失败模式

> 记录 Agent 在本项目中高频出现的错误模式，编码时务必规避

| # | 失败模式 | 违反铁律 | 正确做法 |
|---|---------|---------|---------|
| 1 | 在 ScreenCaptureServer 操作入口跳过 `IsState()` 校验直接执行 | 通用-3 | 每个操作入口先 `CHECK_AND_RETURN_RET_LOG(IsState(CAP_xxx), ...)`，非法状态返回 `MSERR_INVALID_OPERATION` |
| 2 | 新增状态但未更新 `STATE_CAPS_[]` 数组 | 通用-3 | 新增状态枚举值时同步扩展 `STATE_CAPS_[]` 映射，确保 7 个元素对齐 |
| 3 | CreateVirtualScreen 后异常路径未调用 DestroyVirtualScreen | 通用-5 | 所有 CreateVirtualScreen 路径配对 DestroyVirtualScreen，包括 Init 失败、Start 失败、Stop、Release |
| 4 | 跨 IPC 边界传递裸指针或引用 | 通用-1 | 通过 MessageParcel 序列化，客户端持有 Proxy，服务端实现 Stub |
| 5 | 为录屏引入独立引擎层/Pipeline | 通用-2 | 直接调用 Rosen VirtualScreen + AudioCapturer + Recorder 引擎（通过 ScreenCaptureServiceProviders 注入） |
| 6 | 跳过权限校验或隐私授权直接 StartScreenCapture | 通用-4 | Start 前校验 CAPTURE_SCREEN 权限，无 EXEMPT 权限走 POPUP_WINDOW 弹窗流程 |
| 7 | 新增系统监听器但未通过 ListenerManager 统一注册 | 通用-9 | 通过 `RegisterListeners(LF_xxx)` 注册，Server 释放时 `UnregisterListeners(LF_ALL)` 注销 |
| 8 | AcquireVideoBuffer/AcquireAudioBuffer 后未调用对应的 Release | 通用-8 | Acquire 与 Release 严格配对，防止 SurfaceBuffer/AudioBuffer 队列积压 |
| 9 | 回调指针（cbProxy_）跨线程读写未加锁 | 通用-7 | 使用 shared_mutex + shared_lock 保护 cbProxy_ 的读，unique_lock 保护写 |
| 10 | 超限创建录屏实例（全局 >4 或单 UID >4） | 通用-11 | 创建前调用 `SetAndCheckLimit()` / `SetAndCheckSaLimit()` 检查计数 |
| 11 | 通知栏发布后未在 Stop/Release 时移除 | 通用-10 | 录屏开始发布通知，Stop/Release/异常路径均执行通知移除 |
| 12 | 新增 CaptureMode/DataType 枚举值但未校验边界 | 其它-2 | 枚举值校验 MIN_VAL/MAX_VAL 边界，非法值返回错误 |

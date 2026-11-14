# 编码铁律

## 通用编码铁律

> 描述录制框架通用编码规范，采用反模式方式描述

- **禁止**跨层直接调用（如NAPI层直接调用Engine），采用通过IRecorderService/IRecorderEngine接口逐层转发
- **禁止**在非状态允许下执行操作，采用CheckStateMachine/状态校验后再执行
- **禁止**在IPC Proxy调用中忽略返回值，采用检查返回值并上报错误
- **禁止**在Filter中同步等待下游Filter处理完成，采用异步回调OnCallback机制
- **禁止**硬编码编码器名称或格式字符串，采用通过CodecCapabilityAdapter查询能力
- **禁止**在NAPI回调中直接操作JS对象而不在主线程执行，采用napi_call_threadsafe_function
- **禁止**重复调用Stop/Reset/Release导致资源重复释放，采用状态检查防止重复操作
- **禁止**绕过权限检查（MICROPHONE/CAMERA）或 IPC token 验证以通过测试，采用所有入口完整校验
- **禁止**移除或重排 ConfigInfo（Server）或 AVRecorderConfig（NAPI）中经 IPC 序列化的字段，采用新增字段只追加不重排（字段顺序变化破坏 wire 兼容性）
- **禁止**未经跨版本测试修改输出文件格式兼容性（MP4/M4A/AAC track 结构、udta box 布局），采用先验证现有播放客户端兼容再合入
- **禁止**未经许可证审查和审批引入第三方依赖，采用先完成审查（录制服务运行在系统进程，有严格许可证要求）

## 录制状态机编码铁律

- **禁止**在idle状态调用Start/Pause/Resume/Stop，采用先Prepare再操作
- **禁止**在released状态调用任何操作（除Release自身），采用创建新AVRecorder实例
- **禁止**在error状态继续录制操作，采用先Reset或Release恢复
- **禁止**在Prepare之前调用GetInputSurface，采用先Prepare再获取Surface
- **禁止**在非prepared/started/paused状态设置水印，采用在合法状态调用SetWatermark/AddWatermark
- **禁止**修改 AVRecorderState 或 stateCtrlList 时只改单层，采用NAPI（stateCtrlList）、Server（RecStatus）、Engine（StateId）三层状态转换同步验证

## 水印编码铁律

- **禁止**水印数量超过5个，采用添加前校验watermarkCount
- **禁止**水印数据大小超过80MB，采用添加前校验buffer大小
- **禁止**混合使用SetWatermark和AddWatermark的软硬件模式，采用统一使用一种方式

## Pipeline编码铁律

- **禁止**在Pipeline运行时动态增删Filter，采用Stop后Reset再重建Pipeline
- **禁止**Filter间直接持有对方指针，采用通过Pipeline框架和Callback机制通信
- **禁止**在Filter::OnProcess中执行耗时操作，采用异步处理或线程池
- **禁止**忽略Eos事件，采用收到Eos后正确处理并上报完成
- **禁止**未在 FilterFactory 注册并更新 HiRecorderImpl::BuildPipeline 就新增 Filter 类型，采用先注册后接线
- **禁止**直接编辑生成或自动注册的 Filter 绑定，采用更新源码后重新构建

## 资源管理编码铁律

- **禁止**泄漏Surface对象，采用Release时调用RemoveSurface清理
- **禁止**泄漏fd（文件描述符），采用Stop/Reset时调用CloseFd关闭
- **禁止**在WatchDog暂停期间继续操作录制，采用检查watchdogPause_状态
- **禁止**客户端断开后不释放服务端资源，采用DeathRecipient监听客户端死亡
- **禁止**调用 Release 后继续使用 RecorderClient 或 RecorderServer 实例，采用Release 后置空引用
- **禁止**修改 SaveDocumentSyncCallback 关闭处理逻辑而不验证强制停止时录制数据完整性，采用对停止路径做全量测试

## DFX 编码铁律

- **禁止**错误路径返回错误码前不打日志，采用HiLog 带模块标签记录后再返回
- **禁止**录制失败（编码失败/文件写入失败/Pipeline 错误）不上报，采用HiSysEvent fault 事件上报
- **禁止**发送 DFX 事件前未填充 StatisticalEventInfo，采用录制完成或失败时先填齐统计字段再上报
- **禁止**移除或抑制 Filter 中 MEDIA_LOG_I/W/E 日志调用以消除测试输出
- **禁止**禁用 RecorderServer 中 WatchDog，采用保留看门狗防止录制会话挂起

## Agent 常见失败模式

| # | 失败模式 | 违反铁律 | 正确做法 |
|---|---------|---------|---------|
| 1 | 调用 Start 前未调用 Prepare | 状态机-1 | 生命周期方法调用前检查状态，idle 状态先 Prepare |
| 2 | Prepare 前调用 GetInputSurface | 状态机-4 | 先 Prepare 再获取 Surface（仅 Prepare 后可用） |
| 3 | 混用 SetWatermark（硬件）与 AddWatermark（软件）且未检查 IsWatermarkSupported | 水印-3 | 统一一种模式，先查询水印能力 |
| 4 | Stop 后忘记调用 Release | 资源-1/2 | 测试 teardown 中 Stop 后跟 Release，释放 Surface 和 fd |
| 5 | 添加超过 5 个水印 | 水印-1 | 添加前检查 watermarkCount_ |
| 6 | 只在单层修改 stateCtrlList | 状态机-6 | NAPI/Server/Engine 三层同步验证 |

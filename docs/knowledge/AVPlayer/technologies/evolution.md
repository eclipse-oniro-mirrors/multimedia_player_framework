# 模块演进

> 播放引擎、PlayerServer 模块、IPC 通信的版本演进记录。

## 一、播放引擎演进

| 维度 | 说明 |
|------|------|
| 引入版本 | API 9（OH_AVPlayer C API） |
| 主要变更 | API 14：IO 错误码区分（IsAPI14IOError 检查，低版本降级）；连续 Seek（SeekContinous/ExitSeekContinous）；超分辨率（SetSuperResolution）；PCM 输出（SetPCMOutputCallback）；广告媒体源 |
| 废弃 | 无 |

## 二、PlayerServer 模块演进

| 阶段 | 变更内容 |
|------|---------|
| 1. 初始版本 | 基础播放器服务端、8 状态状态机、IPC Stub/Proxy |
| 2. 内存管理 | PlayerServerMem + PlayerMemManage 回收恢复 |
| 3. 后台策略 | AudioBackgroundAdapter + AVsessionBackground |
| 4. 连续 Seek | SeekContinous/ExitSeekContinous 拖拽场景 |
| 5. DRM | SetDecryptConfig 安全视频路径 |
| 6. 广告媒体源 | AddAdsMediaSource/RemoveAdsMediaSource/SkipCurrentAdsMediaSource/DisableAllAdsMediaSource |
| 7. PCM 输出 | SetPCMOutputCallback/SetPCMCallback/SetPCMOutputStatus/SetPCMProcessorStatus/SetPCMProcessorMaxLen |

## 三、IPC 通信演进

| 阶段 | 变更内容 |
|------|---------|
| 1. 初始版本 | 基础 IPC Stub/Proxy：SetSource/Play/Pause/Stop/Seek |
| 2. Listener 增强 | PlayerListenerCallback 桥接类统一回调链 |
| 3. 冻结机制 | Freeze/UnFreeze + SetFreezeFlag IPC 回调冻结 |
| 4. IPC 异常恢复 | DoIpcAbnormality/DoIpcRecovery 客户端死亡和 Binder 断连 |
| 5. 序列化扩展 | AVMediaSource/AVPlayStrategy/AVPlayTrackSelectionFilter 复杂对象 IPC 序列化 |

## 知识关联

- [[architecture]] - 架构总览
- [[design-patterns]] - 设计模式与架构解耦
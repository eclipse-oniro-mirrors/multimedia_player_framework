# 错误处理与 DFX 诊断

> 错误码体系、错误处理策略、DFX 诊断框架、性能监控。

## 一、错误码体系

### 双层错误码

| 层 | 枚举 | 典型值 | 说明 |
|----|------|--------|------|
| C API 层 | OH_AVErrCode | AV_ERR_OK, AV_ERR_INVALID_VAL, AV_ERR_UNKNOWN | 面向应用 |
| 内部层 | MediaServiceErrCode | MSERR_OK, MSERR_SERVICE_DIED, MSERR_INVALID_VAL | 框架内部 |

### 错误码转换

- **MSErrCodeToAVErrCodeApi9**：内部码 → C API 码
- **ERROR_CODE_API9_MAP**：映射表
- **API 14 IO 错误码区分**：PlayerImplCallback 中 IsAPI14IOError 检查，低版本自动降级为 MSERR_DATA_SOURCE_IO_ERROR

## 二、错误处理策略

| 策略 | 说明 |
|------|------|
| 统一返回值 | int32_t 错误码，MSERR_OK(0) 为成功 |
| 参数/状态校验 | CHECK_AND_RETURN_RET_LOG 宏 |
| 引擎错误传播 | OnError/OnErrorMessage 回调经完整 IPC 链 |
| 任务取消 | TaskMgr 新任务取消队列中旧任务 |

### 错误传播链

```
IPlayerEngine error
  → PlayerServer::OnError
  → PlayerListenerCallback
  → Proxy::OnError (IPC)
  → Stub::OnError
  → PlayerCallback::OnError
  → 应用层
```

## 三、DFX 诊断框架

### 七大组件

| 组件 | 说明 |
|------|------|
| MediaEvent | HiSysEvent 上报：behavior/fault/statistics |
| WatchDog | 线程超时检测，"喂狗"机制 |
| PlayerXCollie | 系统级超时 + 死锁检测 + 自动恢复 |
| MediaTrace | 性能追踪 |
| HiAppEventAgent | API 调用追踪 |
| DfxLogDump | 日志转储到文件 |
| ServiceDumpManager | 服务状态快照 |

## 四、播放器 DFX 性能监控

### Native 层 — HiAppEventAgent

- 记录 API 调用性能数据
- 批量上报 + 频率控制

### 引擎层 — DfxAgent

| 方法 | 说明 |
|------|------|
| OnDfxEvent | 诊断事件处理 |
| ReportLagEvent | 卡顿事件上报 |
| SetSourceType | 打点分类 |
| GetTotalStallingDuration/Times | 卡顿统计 |

### DFX 事件类型

| 事件 | 说明 |
|------|------|
| video stutter | 视频卡顿 |
| audio stutter | 音频卡顿 |
| stream stutter | 流卡顿 |
| EOS Seek0 | 结束后 Seek 到 0 |
| performance info | 性能信息 |
| metrics events | 指标事件 |
| playback errors | 播放错误 |

### 关键对象

| 对象 | 说明 |
|------|------|
| HiAppEventAgent | Native 层 API 追踪 |
| DfxAgent | 引擎层卡顿/性能收集 |
| DfxEvent | DFX 事件结构 |
| PlayStatisticalInfo | 播放统计信息 |
| PlayerDfxSourceType | DFX 源类型分类 |

## 知识关联

- [[architecture]] - 架构总览
- [[service-layer]] - 服务层实体
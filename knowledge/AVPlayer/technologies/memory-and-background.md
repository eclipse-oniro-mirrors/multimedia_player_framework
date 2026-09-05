# 内存管理与后台策略

> 内存回收恢复、后台播放策略、冻结解冻、IPC 异常恢复。

## 一、内存回收与恢复

### 核心对象

| 对象 | 职责 |
|------|------|
| PlayerMemManage | 全局单例，监听系统事件，决定回收时机 |
| PlayerServerMem | 执行回收/恢复，继承 PlayerServer |
| AppStateListener | 监听应用前后台切换 |
| RecoverConfigInfo | 保存完整播放状态 |

### 回收策略

| 策略 | 触发条件 | 操作 | 恢复方式 |
|------|---------|------|---------|
| Local 资源回收 | LOW/MODERATE 内存压力 或 前台回收 | 保存 RecoverConfigInfo + Reset 引擎 | 重新初始化引擎 + Seek 回原位 |
| Network 资源回收 | 后台回收 | 释放编解码器 Buffer（HandleCodecBuffers） | 恢复编解码器 Buffer + Seek 回原位 |

### 回收流程

```
系统内存压力/应用后台
  → PlayerMemManage::HandleOnTrim / RecordAppState
  → FindBackGroundPlayerFromVec
  → LocalResourceRelease / NetworkResourceRelease
  → isReleaseMemByManage_ = true
```

### 恢复流程

```
应用前台/用户操作
  → PlayerMemManage::RecoverByMemManage
  → LocalResourceRecover: 重初始化引擎 + 设源 + 配置 + Seek
  → NetworkRecover: 恢复 Buffer + Seek
```

### RecoverConfigInfo 字段

| 字段 | 说明 |
|------|------|
| currState / sourceType / url / dataSrc | 播放状态与源 |
| fd / offset / size | FD 源参数 |
| leftVolume / rightVolume / speedMode | 音量与速度 |
| surface / loop / videoScaleType | 视频与循环 |
| currentTime / playbackPosition | 恢复时 Seek 回此位置 |
| videoTrack / audioTrack / duration | 轨道信息 |

- **代码路径**：`services/services/player/player_mem_manage/`

## 二、后台策略管理

### 音频后台静音

- **AudioBackgroundAdapter**：系统音频策略要求后台应用静音时暂停播放器
- 单例模式，std::call_once 线程安全初始化

### AVSession 管理

- **AVsessionBackground**：未注册 AVSession 的应用强制暂停播放

### 链路

```
系统音频策略 / AVSession 事件
  → AudioBackgroundAdapter / AVsessionBackground
  → IPlayerService::BackGroundChangeState
  → PlayerServer 状态变更
```

## 三、冻结/解冻机制

### 机制说明

- **冻结**：抑制 IPC 回调，部分操作被阻塞
- **解冻**：恢复正常回调通路

### 控制对象

| 对象 | 标志 | 说明 |
|------|------|------|
| PlayerServiceStub | isFrozen_ | 冻结标志 |
| PlayerListenerProxy | isFrozen_ | 回调冻结标志 |

### 任务类型

| 类型 | 说明 |
|------|------|
| FREEZE_TASK | 冻结任务 |
| UNFREEZE_TASK | 解冻任务 |

### 流程

```
冻结：Stub::Freeze → isFrozen_=true → Proxy::SetFreezeFlag(true) → 回调暂停
解冻：逆路径恢复；CheckandDoUnFreeze 自动解冻（特定操作触发）
```

## 四、IPC 异常恢复

### 异常类型

- 客户端死亡
- Binder 通道断开

### 恢复机制

| 方法 | 说明 |
|------|------|
| DoIpcAbnormality | IPC 错误时调用，执行清理 |
| DoIpcRecovery | Monitor 检测恢复时调用，fromMonitor 标志 |
| MonitorClientObject | IPC 连接状态检测 |

### 心跳监控

```
MonitorClientObject::Enable() → 心跳线程启动
  → 定时发送心跳 IPC → MonitorServer 更新最后活跃时间
  → 超时检测线程检查 → 超时触发异常处理
  → 客户端恢复后重新注册心跳
```

## 五、音频中断处理

- **PlayingState** 响应 INTERRUPT_EVENT 消息
- **HandleInterruptEvent**：根据中断类型决定暂停/恢复
- **EnableReportAudioInterrupt**：控制事件上报
- **SetInterruptListenerFlag**：注册中断监听

```
IPlayerEngine → OnInfo(INTERRUPT_EVENT)
  → PlayingState::HandleInterruptEvent
  → 暂停/恢复
  → 回调通知客户端
```

## 知识关联

- [[architecture]] - 架构总览
- [[service-layer]] - 服务层实体
- [[ipc-layer-entities]] - IPC层实体
# 引擎工厂与选择实体

> EngineFactory、EngineFactoryRepo 等引擎选择与加载机制

## 实体概念

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| EngineFactoryRepo | 引擎仓库，管理引擎工厂的注册、加载和打分选择 | Score 对所有注册引擎打分；CreatePlayerEngine 创建最优引擎实例；dlopen/dlsym 动态加载引擎工厂动态库 | 引擎仓库 |
| HstEngineFactory | Histreamer 引擎工厂 | 创建 HiPlayerImpl 实例 | 引擎工厂子类 |
| GstEngineFactory | GStreamer 引擎工厂 | 备选引擎 | 引擎工厂子类 |
| LppEngineFactory | LPP 引擎工厂 | 创建 LppEngine 实例 | 引擎工厂子类 |
| IEngineFactory | 引擎工厂基类接口 | Score 打分；CreatePlayerEngine 创建引擎实例 | 接口 |

### LPP 引擎实体

| 实体名称 | 实体定义 | 核心特征 | 类型/分类 |
|---------|---------|---------|----------|
| LppEngine | 低功耗播放引擎，硬件加速解码/渲染/同步 | HDI 调用硬件解码器/渲染器；LppSyncManager 硬件时钟同步 | 引擎实现 |
| LppSyncManager | 硬件音视频同步管理器 | anchorPts/anchorClock 音频锚点时间戳与时钟；UpdateTimeAnchor 音频渲染器更新锚点；HDI 调用硬件调度视频渲染 | 同步管理 |
| LppAudioStreamerImpl | LPP 音频流实现 | LppAudioDecoderAdapter 解码适配；LppAudioRenderAdapter 渲染适配；LppAudioCallbackLooper 回调循环 | 音频流 |
| LppVideoStreamerImpl | LPP 视频流实现 | LppVideoDecoderAdapter 解码适配；LppVideoCallbackLooper 回调循环 | 视频流 |

## 上下文与场景

### 交互流程

**引擎选择与加载流程**：

```
PlayerServer::InitPlayEngine()
  → EngineFactoryRepo::CreatePlayerEngine(sceneType)
  → Score() 打分选择最优工厂
  → EngineFactory::CreatePlayerEngine()
  → dlopen("libhistreamer_engine.z.so")
  → 返回 HiPlayerImpl 实例
```

**打分选择结果**：

| 场景 | 最优引擎 | 说明 |
|------|---------|------|
| PLAYER（正常播放） | Histreamer | 完整流水线能力 |
| RECORDER | Histreamer | 录制流水线 |
| TRANSCODER | Histreamer | 转码流水线 |
| LPP_STREAMER（低功耗） | LPP | 硬件解码/渲染/同步 |

### 使用场景

| 场景 | 说明 |
|------|------|
| 正常音视频播放 | HstEngineFactory 创建 HiPlayerImpl，完整流水线能力 |
| 低功耗播放 | LppEngineFactory 创建 LppEngine，硬件加速解码/渲染/同步 |
| 录制 | HstEngineFactory 创建录制引擎 |
| 转码 | HstEngineFactory 创建转码引擎 |

### 异常处理路径

| 异常场景 | 处理方式 |
|---------|---------|
| 引擎动态库加载失败 | dlopen 失败时跳过该工厂，继续尝试其它已注册工厂 |
| 所有引擎打分均为 0 | 无法创建引擎，返回创建失败错误 |

## 规格与约束

| 约束类别 | 约束内容 |
|---------|---------|
| 业务规则 | 引擎可替换：新增引擎必须实现 IEngineFactory 接口并通过 dlopen 注册，严禁在服务层硬编码引擎创建逻辑 |
| 业务规则 | 打分机制：EngineFactoryRepo::Score() 按场景类型对所有工厂打分，选择最高分的工厂 |
| 性能约束 | 引擎按需加载：dlopen 懒加载引擎动态库，无播放时不占用内存 |

## 知识关联

| 关联维度 | 关联实体/知识 |
|---------|------------|
| 上层依赖 | [[service-layer]] — PlayerServer 通过 EngineFactoryRepo 创建引擎 |
| 下游影响 | [[engine-layer-entities]] — 工厂创建 HiPlayerImpl 或 LppEngine 实例 |
| 平级关联 | HstEngineFactory ↔ LppEngineFactory — 同级工厂，通过打分竞争选择 |
| 概念对比 | Histreamer vs LPP — 前者完整流水线软硬解能力，后者纯硬件加速低功耗路径 |
| 概念对比 | LppSyncManager vs MediaSyncManager — 前者硬件时钟同步，后者软件时钟同步 |

## 数据模型

### EngineFactoryRepo 数据结构

按动态库路径注册的工厂列表，运行时通过 dlopen 加载并缓存工厂实例。

## 代码与符号

| 实体 | 代码路径 | 核心符号 |
|------|---------|---------|
| EngineFactoryRepo | `services/engine/` | EngineFactoryRepo::Score/CreatePlayerEngine |
| HstEngineFactory | `services/engine/` | HstEngineFactory |
| GstEngineFactory | `services/engine/` | GstEngineFactory |
| LppEngineFactory | `services/engine/` | LppEngineFactory |
| IEngineFactory | — | IEngineFactory::Score/CreatePlayerEngine |
| LppEngine | `services/engine/histreamer/lpp/` | LppEngine |
| LppSyncManager | `services/engine/histreamer/lpp/` | LppSyncManager::UpdateTimeAnchor |
# 编码铁律

## 通用编码铁律

> 描述通用编码规范，必须简洁明了，采用反模式方式描述

- **禁止**跨 IPC 边界直接调用另一进程对象，**采用** IPC Proxy/Stub + MessageParcel 序列化通信
- **禁止**服务层硬编码引擎创建逻辑，**采用** IEngineFactory 接口 + dlopen 注册 + EngineFactoryRepo 打分选择
- **禁止**引擎直接操作 Pipeline 内特定 Filter，**采用** Pipeline 公共接口统一下发（Seek/Stop 等生命周期操作）
- **禁止**服务层直接依赖引擎实现头文件，**采用** InnerAPI 契约头文件解耦（服务层 → InnerAPI ← 引擎层）
- **禁止**绕过 PluginManager 直接加载编解码器，**采用** Sniff 嗅探打分机制注册发现插件
- **禁止**绕过状态机直接变更播放状态，**采用** 8 状态状态机校验，非法操作返回 MSERR_INVALID_STATE
- **禁止**内存回收后不完整恢复播放现场，**采用** RecoverConfigInfo 保存全部状态（源/位置/配置/Surface）
- **禁止**使用缩写或歧义命名，**采用**完整语义化命名（AudioDecoderFilter 非 ADF，BufferQueueProducer 非 BQP）
- **禁止**成员变量与局部变量同名，**采用** trailing_ 后缀标注（isSeeking_、currentState_）
- **禁止**使用 void* 传递业务数据，**采用** std::shared_ptr<AVBuffer> / std::shared_ptr<Plugin> 等强类型
- **禁止**裸指针跨模块传递，**采用** unique_ptr（唯一所有权）或 shared_ptr + weak_ptr（共享所有权打破循环）
- **禁止** C 风格强制类型转换，**采用** static_cast / dynamic_cast / reinterpret_cast 并注明理由
- **禁止**公共头文件与内部实现混放，**采用** InnerAPI 头文件放 interfaces/inner_api/，与 services/ 和 engine/ 严格分离
- **禁止**引擎层目录引入服务层头文件，**采用** 单向依赖：服务层 → InnerAPI ← 引擎层
- **禁止**多线程访问共享状态不加锁，**采用**互斥锁或原子变量保护（taskMgr_、Filter 链、BufferQueue）
- **禁止**持锁状态下调用外部模块未知接口，**采用**锁内只操作本模块数据，跨模块调用释放锁后执行
- **禁止**回调线程执行长时间阻塞操作，**采用**异步任务队列投递耗时处理
- **禁止** IPC OnRemoteRequest 中执行耗时操作，**采用**参数校验 + 任务分发至工作线程
- **禁止** IPC 回调链路同步等待客户端响应，**采用**异步投递

## 其它编码铁律

> 描述安全、内存、性能等编码规范要求

- **禁止**公开 API 跳过权限校验，**采用**所有入口执行权限验证，系统敏感接口校验调用者身份
- **禁止**明文存储 DRM 密钥或解密配置，**采用**安全通道传递，日志/IPC 中严禁泄露密钥
- **禁止** IPC 反序列化跳过参数校验，**采用**校验必要字段存在性 + 取值范围合法性
- **禁止**文件路径不经安全校验直接使用，**采用**路径规范化（防 ../ 穿越）+ 沙箱路径校验
- **禁止** IPC 请求直接传递超 4096 字节大对象，**采用** Ashmem 共享内存或文件描述符传递
- **禁止**动态库加载后不调用 dlclose 释放，**采用** PluginManager 引用计数归零后卸载
- **禁止** BufferQueue 生产者无限写入导致内存膨胀，**采用**容量上限 + 满时生产者阻塞等待
- **禁止** shared_ptr 循环引用不配合 weak_ptr，**采用** Pipeline Filter 上下游、Callback 与引擎间使用 weak_ptr
- **禁止**音频渲染热路径分配堆内存，**采用**预分配 Buffer，严禁每帧 new/malloc
- **禁止**视频解码输出路径冗余数据拷贝，**采用** BufferQueue 零拷贝传递
- **禁止** Seek 操作阻塞 UI 线程，**采用** TaskMgr 异步执行 + 连续 Seek 去重合并
- **禁止**后台播放器不响应内存回收策略，**采用** PlayerMemManage 通知时释放编解码器和 Pipeline 资源
- **禁止** Surface/文件描述符等系统资源不释放，**采用**播放器销毁时断开 Surface、关闭 fd、注销死亡通知
- **禁止** GN 构建遗漏 CFI 安全编译标志，**采用**引擎和插件共享库启用 CFI 强化
- **禁止** versionscript 遗漏导出符号声明，**采用** InnerAPI 导出符号明确声明，未声明符号隐藏

## Agent 常见失败模式

> 记录 Agent 在本项目中高频出现的错误模式，编码时务必规避

| # | 失败模式 | 违反铁律 | 正确做法 |
|---|---------|---------|---------|
| 1 | 在 PlayerServer 直接 `new HiPlayerImpl()` 创建引擎 | 通用-2 | 通过 `EngineFactoryRepo::CreatePlayerEngine()` 创建，由打分机制选择引擎 |
| 2 | 在 HiPlayerImpl 中直接调用特定 Filter 方法（如 `DemuxerFilter::Seek()`） | 通用-3 | 通过 `Pipeline::SendMessage()` 统一下发操作 |
| 3 | 在 PlayerServer 操作入口跳过状态机校验直接执行 | 通用-6 | 每个操作入口先 `CheckCurrentState()`，非法状态返回 `MSERR_INVALID_STATE` |
| 4 | 跨 IPC 边界传递裸指针或引用 | 通用-1 | 通过 MessageParcel 序列化，客户端持有 Proxy，服务端实现 Stub |
| 5 | 新增播放状态变量但未加入 RecoverConfigInfo | 通用-7 | 所有影响播放的配置/状态变更时同步写入 RecoverConfigInfo |
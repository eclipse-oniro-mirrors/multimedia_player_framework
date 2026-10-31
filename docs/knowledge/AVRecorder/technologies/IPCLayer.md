# IPC通信层
 
> 录制框架的客户端-服务端跨进程通信机制
 
## 解决的问题（Problem）
 
| 子维度 | 内容 |
| --- | -- |
| 业务痛点 | 录制服务运行在media_service进程，应用运行在独立进程，需要跨进程调用和回调 |
| 技术目标 | 提供可靠的跨进程通信通道，支持请求-响应和事件回调两种模式 |
| 适用场景 | 所有录制操作的跨进程调用、错误和信息回调上报 |
 
## 核心概念与术语（Concepts）
 
| 子维度 | 内容 |
| --- | -- |
| 关键术语 | IStandardRecorderService（IPC服务接口）、IStandardRecorderListener（IPC回调接口）、Proxy（客户端代理）、Stub（服务端存根） |
| 角色定义 | RecorderClient持有Proxy发起调用；RecorderServer实现Stub接收调用；RecorderListenerStub实现回调Stub |
| 核心对象 | RecorderServiceProxy、RecorderServiceStub、RecorderListenerProxy、RecorderListenerStub |
 
## 原理（Principles）
 
| 子维度 | 内容 |
| --- | -- |
| 核心机制 | OHOS IPC框架：客户端通过Proxy将调用序列化为MessageParcel发送，服务端Stub反序列化并执行，结果通过IPC回复 |
| 架构组成 | 正向调用：RecorderClient → RecorderServiceProxy → IPC → RecorderServiceStub → RecorderServer；反向回调：RecorderServer → RecorderListenerProxy → IPC → RecorderListenerStub → NAPI回调 |
| 关键流程 | 1.Client调用方法 2.Proxy序列化参数写入MessageParcel 3.IPC发送到Server端 4.Stub反序列化并调用Server方法 5.Server执行后将结果写入Reply |
| 数据/控制流 | 控制流双向：Client→Server（请求）、Server→Client（回调） |
 
## 使用方式（Usage）
 
| 子维度 | 内容 |
| --- | -- |
| 接入条件 | 通过RecorderClient::Create(ipcProxy)创建客户端，传入IPC代理对象 |
| 配置步骤 | 框架内部自动管理，应用层无需关心IPC细节 |
| 核心API | IStandardRecorderService（定义所有录制IPC方法）、IStandardRecorderListener（定义所有回调IPC方法） |
| 典型流程 | 创建RecorderClient时自动创建ListenerStub并注册到Proxy |
 
## 代码关联（Code）
 
| 子维度 | 内容 |
| --- | -- |
| 核心类/接口 | RecorderServiceProxy、RecorderServiceStub、RecorderListenerProxy、RecorderListenerStub、IStandardRecorderService、IStandardRecorderListener |
| 关键配置文件 | services/services/recorder/ipc/ 目录下所有文件 |
 
## 约束与限制（Constraints）
 
| 子维度 | 内容 |
| --- | -- |
| 系统限制 | IPC调用有延迟，不适合高频数据传输 |
| 环境依赖 | 依赖OHOS IPC框架和media_service进程 |
| 性能约束 | 每次IPC调用有一次序列化/反序列化开销 |
| 安全约束 | IPC需Token校验，防止未授权调用 |
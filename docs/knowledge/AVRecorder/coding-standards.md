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

## 录制状态机编码铁律

- **禁止**在idle状态调用Start/Pause/Resume/Stop，采用先Prepare再操作
- **禁止**在released状态调用任何操作（除Release自身），采用创建新AVRecorder实例
- **禁止**在error状态继续录制操作，采用先Reset或Release恢复
- **禁止**在Prepare之前调用GetInputSurface，采用先Prepare再获取Surface
- **禁止**在非prepared/started/paused状态设置水印，采用在合法状态调用SetWatermark/AddWatermark

## 水印编码铁律

- **禁止**水印数量超过5个，采用添加前校验watermarkCount
- **禁止**水印数据大小超过80MB，采用添加前校验buffer大小
- **禁止**混合使用SetWatermark和AddWatermark的软硬件模式，采用统一使用一种方式

## Pipeline编码铁律

- **禁止**在Pipeline运行时动态增删Filter，采用Stop后Reset再重建Pipeline
- **禁止**Filter间直接持有对方指针，采用通过Pipeline框架和Callback机制通信
- **禁止**在Filter::OnProcess中执行耗时操作，采用异步处理或线程池
- **禁止**忽略Eos事件，采用收到Eos后正确处理并上报完成

## 资源管理编码铁律

- **禁止**泄漏Surface对象，采用Release时调用RemoveSurface清理
- **禁止**泄漏fd（文件描述符），采用Stop/Reset时调用CloseFd关闭
- **禁止**在WatchDog暂停期间继续操作录制，采用检查watchdogPause_状态
- **禁止**客户端断开后不释放服务端资源，采用DeathRecipient监听客户端死亡

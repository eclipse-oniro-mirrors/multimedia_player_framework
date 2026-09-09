# 设计模式与架构解耦

> ScreenCaptureServer 设计模式总览、与 AVPlayer 设计对比、架构解耦机制。

## 一、ScreenCaptureServer 设计模式总览

| 模式 | 实现类 | 说明 |
|------|--------|------|
| 状态模式 | `IsState(cap)` 能力位图 | 替代 AVPlayer 的 BaseState 子类继承体系 |
| 单例模式 | `ScreenCaptureServerManager`、Monitor | 全局唯一实例管理 |
| 观察者模式 | `ScreenCaptureCallBack` + `ScreenCaptureListenerManager` | 事件回调 + 系统监听器 |
| 工厂模式 | `ScreenCaptureFactory`、`ScreenCaptureControllerFactory` | 实例创建 |
| 代理模式 | `ScreenCaptureCallbackProxy`、`ScreenCaptureListenerCallback` | 回调桥接 |
| Wrapper 模式 | `ScreenCaptureListenerManager` 各 Wrapper | 系统监听器适配 |
| 依赖注入 | `IScreenCaptureServiceProviders` | 服务依赖抽象 |
| Stub/Proxy | IPC 接口对 | 跨进程通信 |
| 作用域守卫 | `ON_SCOPE_EXIT` / `CANCEL_SCOPE_EXIT_GUARD` | 资源安全释放 |

## 二、能力位图状态机（与 Player 状态类对比）

### 对比

| 维度 | AVPlayer | ScreenCapture |
|------|----------|---------------|
| 状态管理 | 8 个 BaseState 子类 | 7 状态枚举 + STATE_CAPS_[] 位图 |
| 状态校验 | `state_->CheckState(operation)` | `IsState(cap)` 位与判断 |
| 状态转换 | 显式 `state_ = NewState()` | `captureState_ = AVScreenCaptureState::Xxx` |
| 能力组合 | 状态类方法决定 | Capability 位组合决定 |

### 优劣分析

| 维度 | 能力位图 | 状态类继承 |
|------|---------|-----------|
| 扩展性 | 新增状态需修改枚举 + STATE_CAPS_ | 新增状态类即可 |
| 查询效率 | O(1) 位与运算 | 虚函数调用 |
| 代码简洁度 | 简洁，一个 `IsState` 覆盖所有 | 每个状态类独立实现 |
| 跨状态能力 | 天然支持（一个状态拥有多 Capability） | 需继承链或多接口 |

### 能力位图核心

```cpp
static constexpr std::array<uint32_t, 7> STATE_CAPS_ = {
    CAP_INIT | CAP_CONFIG | CAP_ALIVE,     // CREATED
    CAP_ALIVE | CAP_POPUP,                  // POPUP_WINDOW
    CAP_ALIVE,                              // STARTING
    CAP_ALIVE | CAP_RUNNING | CAP_ACTIVE,   // STARTED
    CAP_ALIVE | CAP_PAUSED | CAP_ACTIVE,    // PAUSED
    CAP_ALIVE | CAP_RUNNING | CAP_ACTIVE,   // RESUMED
    CAP_INIT,                               // STOPPED
};

bool IsState(uint32_t cap) const {
    return (STATE_CAPS_[captureState_.load()] & cap) != 0;
}
```

## 三、观察者模式 — 事件通知链

### 3.1 录屏事件观察者

```
ScreenCaptureServer（Subject）
  ├── cbProxy_ (ScreenCaptureCallbackProxy)
  │     └─ ScreenCaptureListenerCallback → IPC → 应用层 ScreenCaptureCallBack
  │
  └─ ScreenCaptureListenerManager（系统事件观察者管理器）
        ├── SessionLifecycleListenerWrapper → 窗口生命周期事件
        ├── WindowInfoListenerWrapper → 窗口信息变化
        ├── RecordDisplayListenerWrapper → 录制显示器变化
        ├── PrivateWindowListenerWrapper → 隐私窗口变化
        ├── ScreenConnectListenerWrapper → 屏幕连接/断开
        ├── LanguageSwitchSubscriberWrapper → 语言切换
        ├── AccountObserverCallbackWrapper → 账户切换
        ├── InCallObserverCallbackWrapper → 通话状态变化（条件编译）
        ├── AudioRendererCallbackWrapper → 音频渲染器状态变化
        └── AppLifecycleListenerWrapper → 应用实例生命周期
```

### 3.2 Monitor 观察者

```
ScreenCaptureMonitorServer（Subject）
  └─ 监听器列表
        → CallOnScreenCaptureStarted(pid) → 通知所有监听器
        → CallOnScreenCaptureFinished(pid) → 通知所有监听器
```

## 四、Wrapper 模式 — 监听器管理

`ScreenCaptureListenerManager` 通过 Wrapper 类适配不同系统监听器接口：

| Wrapper | 继承的接口 | 事件 |
|---------|-----------|------|
| `SessionLifecycleListenerWrapper` | `Rosen::SessionLifecycleListenerStub` | 窗口 FOREGROUND/BACKGROUND/DESTROYED |
| `WindowInfoListenerWrapper` | `Rosen::IWindowInfoChangedListener` | 窗口信息变化 |
| `RecordDisplayListenerWrapper` | `Rosen::ScreenManager::IRecordDisplayListener` | 录制显示器变化 |
| `PrivateWindowListenerWrapper` | `Rosen::DisplayManager::IPrivateWindowListener` | 隐私窗口变化 |
| `ScreenConnectListenerWrapper` | `Rosen::ScreenManager::IScreenListener` | 屏幕连接/断开 |
| `LanguageSwitchSubscriberWrapper` | `EventFwk::CommonEventSubscriber` | 语言切换事件 |
| `AccountObserverCallbackWrapper` | `AccountObserverCallBack` | 账户切换 |
| `InCallObserverCallbackWrapper` | `InCallObserverCallBack` | 通话状态（条件编译） |
| `AudioRendererCallbackWrapper` | `AudioStandard::AudioRendererStateChangeCallback` | 音频渲染器状态 |

每个 Wrapper 持有 `weak_ptr<IScreenCaptureEventListener>`，将系统事件转发给 ScreenCaptureServer。

### ListenerFlag 位图控制

```cpp
enum ListenerFlag : uint32_t {
    LF_WIN_LIFECYCLE = 1 << 0,
    LF_WIN_INFO      = 1 << 1,
    LF_RECORD_DISP   = 1 << 2,
    LF_PRIVATE_WIN   = 1 << 3,
    LF_SCREEN_CONN   = 1 << 4,
    LF_LANG_SWITCH   = 1 << 5,
    LF_ACCOUNT       = 1 << 6,
    LF_CALL          = 1 << 7,  // 条件编译
    LF_AUDIO_RENDERER= 1 << 8,
    LF_APP_LIFECYCLE = 1 << 9,
    LF_ALL           = /* 所有标志的或组合 */,
};
```

通过 `RegisterListeners(flags)` 按需注册，`UnregisterListeners(flags)` 按需注销。

## 五、代理模式 — 回调桥接

### 5.1 ScreenCaptureCallbackProxy

```cpp
class ScreenCaptureCallbackProxy : public ScreenCaptureCallBack, public NoCopyable {
    void SetCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback);
    void SetBufferActive(bool active);
    // 实现所有 8 个 ScreenCaptureCallBack 接口，转发给实际回调
};
```

- **bufferActive_**：控制 OnAudioBufferAvailable/OnVideoBufferAvailable 是否通知应用
- 停止录屏时 `SetBufferActive(false)` 阻止后续缓冲回调

### 5.2 ScreenCaptureListenerCallback

```cpp
class ScreenCaptureListenerCallback : public ScreenCaptureCallBack, public NoCopyable {
    explicit ScreenCaptureListenerCallback(const sptr<IStandardScreenCaptureListener> &listener);
    // 将 ScreenCaptureCallBack 接口桥接到 IPC Listener
};
```

将应用层回调接口适配为 IPC 接口，实现跨进程回调传输。

## 六、工厂模式

| 工厂 | 作用 |
|------|------|
| `ScreenCaptureFactory` | InnerAPI 层创建 ScreenCapture 实例（应用调用） |
| `ScreenCaptureControllerFactory` | 创建 ScreenCaptureController 实例 |
| `CreateScreenCaptureServer` (extern C) | 服务端创建 ScreenCaptureServer 实例 |

## 七、IPC Stub/Proxy 模式

| 接口 | Stub（服务端） | Proxy（客户端） |
|------|----------------|----------------|
| IStandardScreenCaptureService | ScreenCaptureServiceStub | ScreenCaptureServiceProxy |
| IStandardScreenCaptureListener | ScreenCaptureListenerStub | ScreenCaptureListenerProxy |
| IStandardScreenCaptureController | ScreenCaptureControllerStub | ScreenCaptureControllerProxy |
| IStandardScreenCaptureMonitorService | MonitorServiceStub | MonitorServiceProxy |
| IStandardScreenCaptureMonitorListener | MonitorListenerStub | MonitorListenerProxy |

## 八、作用域守卫模式

`ON_SCOPE_EXIT(id)` 和 `CANCEL_SCOPE_EXIT_GUARD(id)` 用于关键流程的资源安全释放：

```cpp
int32_t StartStreamHomeVideoCapture() {
    ON_SCOPE_EXIT(0) {
        DestroyVirtualScreen();
        consumer_->UnregisterConsumerListener();
        surfaceCb_->StopBufferThread();
        surfaceCb_->Release();
    };
    // ... 创建资源 ...
    CANCEL_SCOPE_EXIT_GUARD(0);  // 成功则取消守卫
    return MSERR_OK;
}
```

异常路径：守卫自动执行清理；正常路径：`CANCEL_SCOPE_EXIT_GUARD` 取消守卫。

## 九、架构解耦机制

### 9.1 服务与采集实现解耦

ScreenCaptureServer **不经过引擎层**，直接调用 Rosen（显示管理）和 AudioCapturer（音频采集）：

```
应用 → Bridge Layer → Native API → IPC → ScreenCaptureServer
  → 直接调用 Rosen::ScreenManager（虚拟屏幕/镜像）
  → 直接调用 AudioStandard::AudioCapturer（音频采集）
  → 直接调用 IRecorderService（CAPTURE_FILE 模式编码封装）
```

与 AVPlayer 不同，录屏模块无 EngineFactory / Pipeline 架构。

### 9.2 契约层（InnerAPI Headers）

| 头文件 | 接口类 | 说明 |
|--------|--------|------|
| `interfaces/inner_api/native/screen_capture.h` | `ScreenCapture`、`ScreenCaptureCallBack`、`ScreenCaptureFactory` | 录屏主接口 |
| `interfaces/inner_api/native/screen_capture_controller.h` | `ScreenCaptureController` | Picker 用户选择控制器 |
| `interfaces/inner_api/native/screen_capture_monitor.h` | `ScreenCaptureMonitor`、`ScreenCaptureMonitorListener` | 录屏状态监控 |

### 9.3 访问层 / 桥接层

| 层 | 文件 | 说明 |
|----|------|------|
| NAPI | `frameworks/js/avscreen_capture/avscreen_capture_napi.cpp` | JS/ArkTS → Native |
| CJ-FFI | Cangjie 语言 FFI 桥接 | Cangjie → Native |
| C API | `frameworks/native/capi/screencapture/native_avscreen_capture.cpp` | C 接口封装 |
| Native Impl | `frameworks/native/screen_capture/screen_capture_impl.cpp` | Native API 实现 |
| Client | `services/services/screen_capture/client/screen_capture_client.cpp` | IPC 客户端 |

### 9.4 依赖注入

```cpp
class IScreenCaptureServiceProviders {
    virtual IInnerScreenCaptureMonitorService &GetScreenCaptureMonitor() = 0;
    virtual std::shared_ptr<IRecorderService> CreateRecorder() = 0;
    virtual int32_t TryUpdateSettingsValue(const std::string &key, const std::string &value) = 0;
#ifdef SUPPORT_CALL
    virtual InCallObserver &GetInCallObserver() = 0;
#endif
    virtual AccountObserver &GetAccountObserver() = 0;
};
```

通过 `IScreenCaptureServiceProviders` 抽象外部依赖，测试时可注入 Mock。

## 知识关联

- [[capture-lifecycle]] - 录屏完整生命周期
- [[ipc-communication]] - IPC 通信与回调机制
- [[privacy-and-permission]] - 隐私保护与权限机制
- [[flows]] - 关键流程详解
- [[evolution]] - 模块演进记录

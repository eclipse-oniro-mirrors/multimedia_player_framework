---
name: avrecorder-new-interface
description: 当用户需要为AVRecorder模块新增API接口时使用。用户描述接口需求，AI生成NAPI和Taihe层完整代码。仅用于AVRecorder或类似录制模块新增接口。
license: Apache-2.0
compatibility: opencode
metadata:
  audience: developers
  language: cpp
  framework: openharmony
  module: avrecorder
---

## 适用场景

- 为 AVRecorder / AVTranscoder 等媒体录制模块新增 API 接口
- 需要同步生成 NAPI + Taihe 两层完整代码

**不适用**：修bug、重构、与新增接口无关的问题。

## 源码位置

| 层 | 头文件 | 实现文件 |
|----|--------|----------|
| NAPI | `frameworks/js/avrecorder/avrecorder_napi.h` | `frameworks/js/avrecorder/avrecorder_napi.cpp` |
| Taihe | `frameworks/taihe/media/include/avrecorder_taihe.h` | `frameworks/taihe/media/src/avrecorder_taihe.cpp` |
| 数据结构 | `interfaces/inner_api/native/av_common.h` | — |

## 工作流程

### 第1步：确认需求

输出确认表，等用户确认后再生成代码：

```
接口需求确认

接口名称: <Xxx>
功能描述: <描述>
参数列表:
  - param1: type - 必填/可选 - 说明
返回值: Promise<void> / Promise<bool>
允许状态: <根据下表选择>
```

### 第2步：检索上下文

读取上述源码文件，找同类接口作为模板，理解现有代码结构。

### 第3步：生成代码

按顺序输出4个文件的修改内容，每段标注插入位置。

## 状态机允许状态

| 接口类型 | 允许状态 | 示例 |
|----------|----------|------|
| 配置类 | STATE_IDLE, STATE_PREPARED | prepare, setConfig |
| 控制类 | STATE_PREPARED, STATE_STARTED, STATE_PAUSED | start, pause |
| 动态操作 | STATE_STARTED, STATE_PAUSED | addWatermark, setMetadata |
| 查询类 | STATE_PREPARED, STATE_STARTED, STATE_PAUSED | getConfig |
| 清理类 | 所有状态 | release, reset |

## NAPI 与 Taihe 关键差异

| 差异点 | NAPI | Taihe |
|--------|------|-------|
| AsyncContext 创建 | `std::make_unique<AVRecorderAsyncContext>(env)` | `std::make_unique<AVRecorderAsyncContext>()` |
| asyncCtx 主指针 | `asyncCtx->napi` | `asyncCtx->taihe` |
| 调用方式 | Promise 异步（napi_create_async_work） | Sync 同步（直接 GetResult） |
| 错误上报 | `asyncCtx->AVRecorderSignError(...)` | `SetRetInfoError(...)` |
| 结果错误 | `asyncCtx->SignError(...)` | `set_business_error(...)` |
| Config 参数来源 | 从 JS napi_value 解析（CommonNapi::GetPropertyInt32） | 从 Taihe IDL const& 直接赋值 |

## 错误码处理

新增接口必须正确处理从内部 MSERR_* 到对外 API9 码的映射。涉及3个环节：

### 错误传递链路

```
内部码 MSERR_* → MSErrorToExtErrorAPI9() → API9码 MSERR_EXT_API9_* → JS层 BusinessError
```

### 环节1：参数验证阶段 — AVRecorderSignError / SetRetInfoError

在 Js 函数或 GetConfig 中，参数不合法时直接报错：

**NAPI**：`asyncCtx->AVRecorderSignError(errCode, operate, param, add)`
```cpp
// 内部调用链：AVRecorderSignError → GetRetInfo → MSErrorToExtErrorAPI9 → MSExtErrorAPI9ToString → SignError
// 例：参数类型错误
asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "Get<Xxx>Config", "<Xxx>Config");
// 例：参数范围错误（带补充信息）
asyncCtx->AVRecorderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "Get<Xxx>Config", "top",
    "config top cannot be null or less than zero");
// 例：状态机不允许
asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
```

**Taihe**：`SetRetInfoError(errCode, operate, param, add)`
```cpp
// 内部调用链：SetRetInfoError → MSErrorToExtErrorAPI9 → MSExtErrorAPI9ToString → set_business_error
// 例：参数范围错误
SetRetInfoError(MSERR_PARAMETER_VERIFICATION_FAILED, "Get<Xxx>Config", "top",
    "config top cannot be less than zero");
// 例：PixelMap 为空
SetRetInfoError(MSERR_INVALID_VAL, "GetPixelMap", "PixelMap");
```

### 环节2：Task 执行阶段 — GetRetInfo

Task 内调用实现函数失败时，用 `GetRetInfo` 构造 RetInfo：

```cpp
// NAPI 和 Taihe 都用同一个 GetRetInfo 函数（各自的文件中有定义）
// 调用链：GetRetInfo → MSErrorToExtErrorAPI9 → MSExtErrorAPI9ToString
CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(ret, "<Xxx>Task", ""), "<Xxx>Task failed");
```

GetRetInfo 的4个参数含义：
| 参数 | 含义 | 何时用 |
|------|------|--------|
| `errCode` | 内部 MSERR_* 码 | 直接传底层返回值 |
| `operate` | 操作名（如"SetWatermarkTask"） | 非 INVALID_PARAMETER 时作为消息主体 |
| `param` | 参数名（如"top"） | INVALID_PARAMETER 时作为消息主体 |
| `add` | 补充说明 | 附加到自动生成的消息末尾 |

**消息生成规则**：
- `MSERR_EXT_API9_INVALID_PARAMETER` → "The Parameter **param** is invalid. Please check the type and range." + add

### 环节3：运行时回调 — OnError

底层异步报错（如编码失败、IO超时）通过 OnError 回调传到 JS。新接口如需特定错误映射，修改 OnError：

```cpp
// NAPI: frameworks/js/avrecorder/avrecorder_callback.cpp
// Taihe: frameworks/taihe/media/src/avrecorder_callback_taihe.cpp
void AVRecorderCallback::OnError(RecorderErrorType errorType, int32_t errCode)
{
    // 已知场景保持原映射
    if (errCode == MSERR_DATA_SOURCE_IO_ERROR) {
        SendErrorCallback(MSERR_EXT_API9_TIMEOUT, "The video input stream timed out...");
    } else if (errCode == MSERR_<NEW_SPECIFIC_CODE>) {
        // 新增特定映射
        SendErrorCallback(MSERR_EXT_API9_<TARGET>, "<precise message>");
    } else {
        SendErrorCallback(MSERR_EXT_API9_IO, "IO error happened.");
    }
}
```

### 内部码 → API9码 常用映射速查

| 内部码 MSERR_* | API9码 MSERR_EXT_API9_* | 数值 | 含义 |
|----------------|------------------------|------|------|
| MSERR_OK | MSERR_EXT_API9_OK | — | 成功 |
| MSERR_INVALID_VAL | MSERR_EXT_API9_INVALID_PARAMETER | 401 | 参数无效 |
| MSERR_PARAMETER_VERIFICATION_FAILED | MSERR_EXT_API9_INVALID_PARAMETER | 401 | 参数验证失败 |
| MSERR_INVALID_OPERATION | MSERR_EXT_API9_OPERATE_NOT_PERMIT | 5400102 | 操作不允许 |
| MSERR_INVALID_STATE | MSERR_EXT_API9_OPERATE_NOT_PERMIT | 5400102 | 状态不允许 |
| MSERR_NO_MEMORY | MSERR_EXT_API9_NO_MEMORY | 5400101 | 内存不足 |
| MSERR_VID_ENC_FAILED | MSERR_EXT_API9_IO | 5400103 | 视频编码失败 |
| MSERR_AUD_ENC_FAILED | MSERR_EXT_API9_IO | 5400103 | 音频编码失败 |
| MSERR_OPEN_FILE_FAILED | MSERR_EXT_API9_IO | 5400103 | 文件打开失败 |
| MSERR_UNKNOWN | MSERR_EXT_API9_IO | 5400103 | 未知错误 |
| MSERR_NETWORK_TIMEOUT | MSERR_EXT_API9_TIMEOUT | 5400104 | 超时 |
| MSERR_AUD_INTERRUPT | MSERR_EXT_API9_AUDIO_INTERRUPTED | 5400107 | 音频中断 |
| MSERR_UNSUPPORT_WATER_MARK | MSERR_EXT_API9_UNSUPPORT_CAPABILITY | 801 | 不支持水印 |

**注意**：如需新增内部错误码（如 MSERR_<NEW>_FAILED），需在 `media_errors.h` 定义码值，并在 `media_errors.cpp` 的 `MSERRCODE_INFOS` 和 `MSERRCODE_TO_EXTERRORCODEAPI9` 两个 map 中注册映射。

### 错误码处理规则

1. **参数验证**用 `AVRecorderSignError`（NAPI）/ `SetRetInfoError`（Taihe），自动走 MSErrorToExtErrorAPI9 映射
2. **Task 内失败**用 `GetRetInfo(ret, operate, "")`，自动走映射
3. **状态机拒绝**用 `MSERR_INVALID_OPERATION`，映射到 `MSERR_EXT_API9_OPERATE_NOT_PERMIT`
4. **重复操作**返回 `RetInfo(MSERR_EXT_API9_OK, "")`（静默成功，不报错）
5. **新增特定场景映射**只改 OnError 的 switch/if 分支，不改 MSErrorToExtErrorAPI9 表
6. **不要猜测原因**：错误消息只说实际错误，不写 "Possible reasons: 1. 2. 3..."

## 代码模板

以下为通用模板，`<Xxx>` 替换为新接口名。分为**无参数版**和**带配置参数版**两种。

---

### 一、NAPI 层

#### 1. avrecorder_napi.h 新增内容

**AVRecordergOpt 常量**：
```cpp
namespace AVRecordergOpt {
    // ...existing...
    const std::string <XXX> = "<Xxx>";
}
```

**stateCtrlList 允许状态**：
```cpp
{AVRecorderState::STATE_<STATE>, {
    // ...existing...
    AVRecordergOpt::<XXX>,
}},
```

**AVRecorderNapi 类声明**：

无参数版：
```cpp
static napi_value Js<Xxx>(napi_env env, napi_callback_info info);
static std::shared_ptr<TaskHandler<RetInfo>> <Xxx>Task(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
int32_t <Xxx>();
```

带配置参数版：
```cpp
static napi_value Js<Xxx>(napi_env env, napi_callback_info info);
static std::shared_ptr<TaskHandler<RetInfo>> <Xxx>Task(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
int32_t <Xxx>(std::shared_ptr<<Xxx>Config> &config);
int32_t Get<Xxx>Parameter(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    napi_env env, napi_value args[<maxParam>]);
int32_t Get<Xxx>Config(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    napi_env env, napi_value args);
```

**AVRecorderAsyncContext 新增字段**（带配置参数时）：
```cpp
struct AVRecorderAsyncContext : public MediaAsyncContext {
    // ...existing...
    std::shared_ptr<<Xxx>Config> <xxx>Config_ = nullptr;
};
```

#### 2. avrecorder_napi.cpp 新增内容

**Init() 注册**：
```cpp
DECLARE_NAPI_FUNCTION("<xxx>", Js<Xxx>),
```

**Js<Xxx> — 无参数版**：
```cpp
napi_value AVRecorderNapi::Js<Xxx>(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVRecorder::Js<Xxx>");
    const std::string &opt = AVRecordergOpt::<XXX>;
    MEDIA_LOGI("Js %{public}s Start", opt.c_str());

    size_t argCount = 0;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx != nullptr, result, "failed to get AsyncContext");
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, nullptr);
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi != nullptr, result, "failed to GetJsInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->napi->taskQue_ != nullptr, result, "taskQue is nullptr!");

    asyncCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = AVRecorderNapi::<Xxx>Task(asyncCtx);
        (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        asyncCtx->opt_ = opt;
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, opt.c_str(), NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void* data) {
        AVRecorderAsyncContext* asyncCtx = reinterpret_cast<AVRecorderAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");
        if (asyncCtx->task_) {
            auto result = asyncCtx->task_->GetResult();
            if (result.Value().first != MSERR_EXT_API9_OK) {
                asyncCtx->SignError(result.Value().first, result.Value().second);
            }
        }
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated));
    asyncCtx.release();

    MEDIA_LOGI("Js %{public}s End", opt.c_str());
    return result;
}
```

**Js<Xxx> — 带配置参数版**：

与无参数版的区别仅在：
- `argCount = maxParam`，声明 `napi_value args[maxParam]`
- `GetJsInstanceAndArgs(env, info, argCount, args)` 传入 args
- 状态机检查后先调用 `Get<Xxx>Parameter(asyncCtx, env, args...)` 解析参数
- 参数解析成功后才创建 Task

```cpp
napi_value AVRecorderNapi::Js<Xxx>(napi_env env, napi_callback_info info)
{
    // ...前半部分同无参数版，区别如下...
    const int32_t maxParam = <N>;  // 参数个数
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->napi->Get<Xxx>Parameter(asyncCtx, env, args...) == MSERR_OK) {
            asyncCtx->task_ = AVRecorderNapi::<Xxx>Task(asyncCtx);
            (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }
    // ...后半部分同无参数版（napi_create_async_work + release）...
}
```

**Get<Xxx>Config — 参数解析（NAPI）**：
```cpp
int32_t AVRecorderNapi::Get<Xxx>Config(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    napi_env env, napi_value args)
{
    CHECK_AND_RETURN_RET(CommonNapi::CheckValueType(env, args, napi_object),
        (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "Get<Xxx>Config", "<Xxx>Config"), MSERR_INVALID_VAL));

    asyncCtx-><xxx>Config_ = std::make_shared<<Xxx>Config>();

    // 必填参数：直接取值 + 范围验证
    bool ret = CommonNapi::GetPropertyInt32(env, args, "<param>", asyncCtx-><xxx>Config_-><param>);
    CHECK_AND_RETURN_RET(ret && asyncCtx-><xxx>Config_-><param> >= 0,
        (asyncCtx->AVRecorderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "Get<Xxx>Config", "<param>",
            "config <param> cannot be null or less than zero"), MSERR_PARAMETER_VERIFICATION_FAILED));

    // 可选参数：先检查属性是否存在，再取值
    if (CommonNapi::CheckhasNamedProperty(env, args, "<optionalParam>")) {
        ret = CommonNapi::GetPropertyInt32(env, args, "<optionalParam>", asyncCtx-><xxx>Config_-><optionalParam>);
        CHECK_AND_RETURN_RET(ret && asyncCtx-><xxx>Config_-><optionalParam> > 0,
            (asyncCtx->AVRecorderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "Get<Xxx>Config", "<optionalParam>",
                "config <optionalParam> must be greater than zero"), MSERR_PARAMETER_VERIFICATION_FAILED));
    }
    return MSERR_OK;
}
```

**<Xxx>Task — Task处理函数（NAPI）**：
```cpp
std::shared_ptr<TaskHandler<RetInfo>> AVRecorderNapi::<Xxx>Task(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([napi = asyncCtx->napi,
        &<param1> = asyncCtx-><param1>_ /*, 更多参数按需capture */]() {
        const std::string &option = AVRecordergOpt::<XXX>;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(napi != nullptr, GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        CHECK_AND_RETURN_RET(napi->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        CHECK_AND_RETURN_RET(napi->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = napi-><Xxx>(<param1>);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(ret, "<Xxx>Task", ""),
            "<Xxx>Task failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}
```

**<Xxx> — 实际实现函数（NAPI）**：
```cpp
int32_t AVRecorderNapi::<Xxx>(<参数列表>)
{
    // 根据接口业务逻辑实现
    // 如有配置参数：将参数传递给 recorder_ 底层
    return recorder_-><Xxx>(<参数>);
}
```

---

### 二、Taihe 层

#### 3. avrecorder_taihe.h 新增内容

**AVRecordergOpt 常量** 和 **stateCtrlList**：与 NAPI 层保持一致。

**<Xxx>Config 结构**：与 NAPI 层保持一致。

**AVRecorderImpl 类声明**：

无参数版：
```cpp
bool <Xxx>Sync();  // 返回值类型根据接口定
std::shared_ptr<TaskHandler<RetInfo>> <Xxx>Task(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
int32_t <Xxx>();
```

带配置参数版：
```cpp
void <Xxx>Sync(::ohos::multimedia::media::<Xxx>Config const& config);
std::shared_ptr<TaskHandler<RetInfo>> <Xxx>Task(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx);
int32_t <Xxx>(std::shared_ptr<<Xxx>Config> &config);
int32_t Get<Xxx>Parameter(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::<Xxx>Config const& config);
int32_t Get<Xxx>Config(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::<Xxx>Config const& config);
```

**AVRecorderAsyncContext 新增字段**：与 NAPI 层保持一致。

#### 4. avrecorder_taihe.cpp 新增内容

**<Xxx>Sync — Sync入口（Taihe）**：

无参数版：
```cpp
bool AVRecorderImpl::<Xxx>Sync()
{
    MediaTrace trace("AVRecorder::<Xxx>Sync");
    const std::string &opt = AVRecordergOpt::<XXX>;
    MEDIA_LOGI("Taihe %{public}s Start", opt.c_str());

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    asyncCtx->taihe = this;
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe != nullptr, false, "failed to GetInstanceAndArgs");
    CHECK_AND_RETURN_RET_LOG(asyncCtx->taihe->taskQue_ != nullptr, false, "taskQue is nullptr!");

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        asyncCtx->task_ = <Xxx>Task(asyncCtx);
        (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
    }
    asyncCtx.release();
    MEDIA_LOGI("Taihe %{public}s End", opt.c_str());
    return <返回值>;
}
```

带配置参数版：

与无参数版的区别仅在：状态机检查后先调用 `Get<Xxx>Parameter` 解析参数，参数解析成功后才创建 Task。

```cpp
void AVRecorderImpl::<Xxx>Sync(::ohos::multimedia::media::<Xxx>Config const& config)
{
    // ...前半部分同...
    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->taihe->Get<Xxx>Parameter(asyncCtx, config) == MSERR_OK) {
            asyncCtx->task_ = <Xxx>Task(asyncCtx);
            (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    // ...后半部分同...
}
```

**Get<Xxx>Config — 参数解析（Taihe）**：

与 NAPI 的区别：参数从 Taihe IDL const& 直接赋值，而非从 napi_value 解析。报错用 `SetRetInfoError`。

```cpp
int32_t AVRecorderImpl::Get<Xxx>Config(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ::ohos::multimedia::media::<Xxx>Config const& config)
{
    asyncCtx-><xxx>Config_ = std::make_shared<<Xxx>Config>();
    asyncCtx-><xxx>Config_-><param> = config.<param>;
    CHECK_AND_RETURN_RET(asyncCtx-><xxx>Config_-><param> >= 0,
        (SetRetInfoError(MSERR_PARAMETER_VERIFICATION_FAILED, "Get<Xxx>Config", "<param>",
            "config <param> cannot be less than zero"), MSERR_PARAMETER_VERIFICATION_FAILED));
    return MSERR_OK;
}
```

**<Xxx>Task — Task处理函数（Taihe）**：

与 NAPI 的区别：lambda capture 用 `taihe = asyncCtx->taihe` 而非 `napi = asyncCtx->napi`。

```cpp
std::shared_ptr<TaskHandler<RetInfo>> AVRecorderImpl::<Xxx>Task(
    const std::unique_ptr<AVRecorderAsyncContext> &asyncCtx)
{
    return std::make_shared<TaskHandler<RetInfo>>([taihe = asyncCtx->taihe,
        &<param1> = asyncCtx-><param1>_ /*, 更多参数 */]() {
        const std::string &option = AVRecordergOpt::<XXX>;
        MEDIA_LOGI("%{public}s Start", option.c_str());

        CHECK_AND_RETURN_RET(taihe != nullptr, GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        CHECK_AND_RETURN_RET(taihe->CheckStateMachine(option) == MSERR_OK,
            GetRetInfo(MSERR_INVALID_OPERATION, option, ""));
        CHECK_AND_RETURN_RET(taihe->CheckRepeatOperation(option) == MSERR_OK,
            RetInfo(MSERR_EXT_API9_OK, ""));

        int32_t ret = taihe-><Xxx>(<param1>);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, GetRetInfo(ret, "<Xxx>Task", ""),
            "<Xxx>Task failed");

        MEDIA_LOGI("%{public}s End", option.c_str());
        return RetInfo(MSERR_EXT_API9_OK, "");
    });
}
```

**<Xxx> — 实际实现函数（Taihe）**：
```cpp
int32_t AVRecorderImpl::<Xxx>(<参数列表>)
{
    // 业务逻辑实现，与 NAPI 层类似
    return recorder_-><Xxx>(<参数>);
}
```

---

## 完整范例：SetWatermark

以 `SetWatermark(watermark: PixelMap, config: WatermarkConfig)` 为例，展示带特殊类型（PixelMap）的接口如何扩展通用模板。

**特殊之处**：
- 需从 JS/Taihe 获取 PixelMap 对象
- 需将 PixelMap 数据拷贝到 SurfaceBuffer/AVBuffer，设置 Meta tag，传给底层

### NAPI 层 — JsSetWatermark

```cpp
napi_value AVRecorderNapi::JsSetWatermark(napi_env env, napi_callback_info info)
{
    const std::string &opt = AVRecordergOpt::SET_WATERMARK;
    const int32_t maxParam = 2;
    size_t argCount = maxParam;
    napi_value args[maxParam] = { nullptr };
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>(env);
    asyncCtx->napi = AVRecorderNapi::GetJsInstanceAndArgs(env, info, argCount, args);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, nullptr, result);

    if (asyncCtx->napi->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->napi->GetWatermarkParameter(asyncCtx, env, args[0], args[1]) == MSERR_OK) {
            asyncCtx->task_ = AVRecorderNapi::SetWatermarkTask(asyncCtx);
            (void)asyncCtx->napi->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        asyncCtx->AVRecorderSignError(MSERR_INVALID_OPERATION, opt, "");
    }
    // ...napi_create_async_work + release（同通用模板）...
}
```

### NAPI 层 — GetWatermarkParameter + GetWatermark + GetWatermarkConfig

```cpp
int32_t AVRecorderNapi::GetWatermarkParameter(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    napi_env env, napi_value watermark, napi_value config)
{
    // PixelMap 特殊处理
    asyncCtx->pixelMap_ = Media::PixelMapNapi::GetPixelMap(env, watermark);
    CHECK_AND_RETURN_RET(asyncCtx->pixelMap_ != nullptr,
        (asyncCtx->AVRecorderSignError(MSERR_INVALID_VAL, "GetPixelMap", "PixelMap"), MSERR_INVALID_VAL));

    int32_t ret = GetWatermarkConfig(asyncCtx, env, config);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "failed to GetWatermarkConfig");
    return MSERR_OK;
}

int32_t AVRecorderNapi::GetWatermarkConfig(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    napi_env env, napi_value args)
{
    asyncCtx->watermarkConfig_ = std::make_shared<WatermarkConfig>();
    bool ret = CommonNapi::GetPropertyInt32(env, args, "top", asyncCtx->watermarkConfig_->top);
    CHECK_AND_RETURN_RET(ret && asyncCtx->watermarkConfig_->top >= 0,
        (asyncCtx->AVRecorderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermarkConfig", "top",
            "config top cannot be null or less than zero"), MSERR_PARAMETER_VERIFICATION_FAILED));
    ret = CommonNapi::GetPropertyInt32(env, args, "left", asyncCtx->watermarkConfig_->left);
    CHECK_AND_RETURN_RET(ret && asyncCtx->watermarkConfig_->left >= 0,
        (asyncCtx->AVRecorderSignError(MSERR_PARAMETER_VERIFICATION_FAILED, "GetWatermarkConfig", "left",
            "config left cannot be null or less than zero"), MSERR_PARAMETER_VERIFICATION_FAILED));
    return MSERR_OK;
}
```

### NAPI 层 — SetWatermark 实现（PixelMap → SurfaceBuffer → AVBuffer）

```cpp
int32_t AVRecorderNapi::SetWatermark(std::shared_ptr<PixelMap> &pixelMap,
    std::shared_ptr<WatermarkConfig> &watermarkConfig)
{
    CHECK_AND_RETURN_RET_LOG(pixelMap->GetPixelFormat() == PixelFormat::RGBA_8888,
        MSERR_INVALID_VAL, "Invalid pixel format");

    std::shared_ptr<Meta> avBufferConfig = std::make_shared<Meta>();
    int32_t ret = ConfigAVBufferMeta(pixelMap, watermarkConfig, avBufferConfig);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "ConfigAVBufferMeta is failed");

    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    BufferRequestConfig bufferConfig = {
        .width = pixelMap->GetWidth(), .height = pixelMap->GetHeight(),
        .strideAlignment = 0x8,
        .format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
    };
    surfaceBuffer->Alloc(bufferConfig);

    for (int i = 0; i < pixelMap->GetHeight(); i++) {
        ret = memcpy_s(
            static_cast<uint8_t *>(surfaceBuffer->GetVirAddr()) + i * surfaceBuffer->GetStride(),
            pixelMap->GetRowStride(),
            pixelMap->GetPixels() + i * pixelMap->GetRowStride(),
            pixelMap->GetRowStride());
        CHECK_AND_RETURN_RET_LOG(ret == 0, MSERR_INVALID_VAL, "memcpy failed");
    }

    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(surfaceBuffer);
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, MSERR_NO_MEMORY, "buffer is nullptr");
    buffer->meta_ = avBufferConfig;
    return recorder_->SetWatermark(buffer);
}
```

### Taihe 层 — SetWatermarkSync

```cpp
void AVRecorderImpl::SetWatermarkSync(
    ::ohos::multimedia::image::image::weak::PixelMap watermark,
    ::ohos::multimedia::media::WatermarkConfig const& config)
{
    const std::string &opt = AVRecordergOpt::SET_WATERMARK;
    auto asyncCtx = std::make_unique<AVRecorderAsyncContext>();
    asyncCtx->taihe = this;

    if (asyncCtx->taihe->CheckStateMachine(opt) == MSERR_OK) {
        if (asyncCtx->taihe->GetWatermarkParameter(asyncCtx, watermark, config) == MSERR_OK) {
            asyncCtx->task_ = SetWatermarkTask(asyncCtx);
            (void)asyncCtx->taihe->taskQue_->EnqueueTask(asyncCtx->task_);
        }
    } else {
        SetRetInfoError(MSERR_INVALID_OPERATION, opt, "");
    }
    if (asyncCtx->task_) {
        auto result = asyncCtx->task_->GetResult();
        if (result.Value().first != MSERR_EXT_API9_OK) {
            set_business_error(result.Value().first, result.Value().second);
        }
    }
    asyncCtx.release();
}
```

### Taihe 层 — GetWatermark（PixelMap 获取用 Image::PixelMapImpl）

```cpp
int32_t AVRecorderImpl::GetWatermark(std::unique_ptr<AVRecorderAsyncContext> &asyncCtx,
    ::ohos::multimedia::image::image::weak::PixelMap watermark)
{
    asyncCtx->pixelMap_ = Image::PixelMapImpl::GetPixelMap(watermark);
    CHECK_AND_RETURN_RET(asyncCtx->pixelMap_ != nullptr,
        (SetRetInfoError(MSERR_INVALID_VAL, "GetPixelMap", "PixelMap"), MSERR_INVALID_VAL));
    return MSERR_OK;
}
```

### Taihe 层 — SetWatermark 实现（SurfaceBuffer 用 Image:: 前缀）

```cpp
int32_t AVRecorderImpl::SetWatermark(std::shared_ptr<PixelMap> &pixelMap,
    std::shared_ptr<WatermarkConfig> &watermarkConfig)
{
    // 与 NAPI 实现结构相同，类型前缀不同：
    // SurfaceBuffer → Image::sptr<Image::SurfaceBuffer>
    // BufferRequestConfig → Image::BufferRequestConfig
    // GraphicPixelFormat → Image::GraphicPixelFormat
    // BUFFER_USAGE_* → Image::BUFFER_USAGE_*

    CHECK_AND_RETURN_RET_LOG(pixelMap->GetPixelFormat() == OHOS::Media::PixelFormat::RGBA_8888,
        MSERR_INVALID_VAL, "Invalid pixel format");

    std::shared_ptr<Meta> avBufferConfig = std::make_shared<Meta>();
    int32_t ret = ConfigAVBufferMeta(pixelMap, watermarkConfig, avBufferConfig);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "ConfigAVBufferMeta is failed");

    Image::sptr<Image::SurfaceBuffer> surfaceBuffer = Image::SurfaceBuffer::Create();
    Image::BufferRequestConfig bufferConfig = { /* 同 NAPI，加 Image:: 前缀 */ };
    surfaceBuffer->Alloc(bufferConfig);
    // ...memcpy_s 循环同 NAPI...

    std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(surfaceBuffer);
    buffer->meta_ = avBufferConfig;
    return recorder_->SetWatermark(buffer);
}
```

## 参考文件行号速查

| 用途 | 文件 | 行号 |
|------|------|------|
| NAPI Init 注册 | `avrecorder_napi.cpp` | ~66-118 |
| NAPI Js 函数（无参） | `avrecorder_napi.cpp` | ~1259 (JsIsWatermarkSupported) |
| NAPI Js 函数（带参） | `avrecorder_napi.cpp` | ~357 (JsSetWatermark) |
| NAPI 参数解析 | `avrecorder_napi.cpp` | ~2363 |
| NAPI Config解析 | `avrecorder_napi.cpp` | ~2384 |
| NAPI Task | `avrecorder_napi.cpp` | ~1603 |
| NAPI 实现 | `avrecorder_napi.cpp` | ~1814 |
| Taihe Sync（无参） | `avrecorder_taihe.cpp` | ~1348 (IsWatermarkSupportedSync) |
| Taihe Sync（带参） | `avrecorder_taihe.cpp` | ~1597 (SetWatermarkSync) |
| Taihe 参数解析 | `avrecorder_taihe.cpp` | ~1627 |
| Taihe Config解析 | `avrecorder_taihe.cpp` | ~1647 |
| Taihe Task | `avrecorder_taihe.cpp` | ~1663 |
| Taihe 实现 | `avrecorder_taihe.cpp` | ~1695 |
| stateCtrlList | `avrecorder_napi.h` | ~76-144 |
| AsyncContext | `avrecorder_napi.h` | ~463-484 |
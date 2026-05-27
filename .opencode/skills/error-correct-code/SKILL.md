---
name: error-correct-code
description: 当媒体模块错误码覆盖场景过多或错误信息不够精确时使用。追溯完整错误传递链路（Filter→Pipeline→Engine→Server→NAPI→JS），将通用错误码替换为精确错误码，消除"可能原因"式猜测。仅用于错误码精细化修改。
license: Apache-2.0
compatibility: opencode
metadata:
  audience: developers
  language: cpp
  framework: openharmony
  module: avrecorder
---

## 适用场景

- 单个错误码覆盖10+场景（如 MSERR_UNKNOWN 广泛使用）
- 错误信息猜测"可能原因"而非陈述事实
- 底层精确码被统一映射成通用码
- 需要让用户根据错误码直接定位问题

**不适用**：新增功能、无关重构、通用调试。

## 核心原则

| 原则 | 做法 |
|------|------|
| 精准不猜测 | ✅ "Failed to encode video." ❌ "Possible reasons: 1. Hardware unavailable..." |
| 范围限定 | 只改核心模块，及时撤销非核心修改 |
| 链路完整 | 追溯 Filter→Pipeline→Engine→Server→NAPI→JS，确保精确码到达 JS 层 |
| 验证闭环 | git diff → 编译 → 测试 |

## 分析流程（5步）

### 第1步：统计错误码分布

```powershell
rg "MSERR_UNKNOWN|Status::ERROR_UNKNOWN" --type cpp -c
rg "MSERR_UNKNOWN" --type cpp -l | sort
```

### 第2步：追溯错误传递链路

```
Filter → Pipeline → Engine → Server → NAPI → JS
```

关键节点：
- Filter: `eventReceiver_->OnEvent({source, EVENT_ERROR, errorCode})`
- Engine: `obs_.lock()->OnError(errorType, errorCode)`
- Server: `recorderCb_->OnError(errorType, errorCode)`
- NAPI: `SendErrorCallback(extErr, message)`
- JS: `napi_call_function`

### 第3步：找到关键映射函数

| 函数 | 作用 |
|------|------|
| `OnError` | 底层码 → 上层码 |
| `GetRetInfo` | 错误码 → 错误消息 |
| `MSErrorToExtErrorAPI9` | 内部码 → API9码 |

检查重点：`default` 是否统一映射成通用码？是否有精确码的 switch-case？

### 第4步：分析 JS 层回调链路

```
avRecorder.on('error', callback)
  → JsSetEventCallback → SetCallbackReference → refMap_["error"]
  → SendErrorCallback → OnJsErrorCallBack → napi_call_function
```

### 第5步：确定修改策略

| 策略 | 修改范围 | 适用 |
|------|----------|------|
| A | 仅 NAPI 层 | 底层码已精确，仅消息模糊 |
| B | Engine + NAPI | 底层统一映射，需返回精确码 |
| C | Filter + Engine + NAPI | Filter层码本身不精确（慎用） |

## 修改实施（4步）

### 第1步：撤销非核心修改

```bash
git checkout -- <非核心文件>
```

### 第2步：修改关键函数

**OnError 精细化（NAPI层）**：
```cpp
void AVRecorderCallback::OnError(RecorderErrorType errorType, int32_t errCode)
{
    MediaServiceExtErrCodeAPI9 extErr = MSErrorToExtErrorAPI9(...);
    std::string message;
    switch (errCode) {
        case MSERR_VID_ENC_FAILED:  message = "Failed to encode video."; break;
        case MSERR_AUD_ENC_FAILED:  message = "Failed to encode audio."; break;
        default:                    message = "IO error."; break;
    }
    SendErrorCallback(extErr, message);
}
```

**GetRetInfo 精细化（NAPI层）**：
```cpp
if (err == MSERR_EXT_API9_IO) {
    std::string message;
    switch (errCode) {
        case MSERR_VID_ENC_FAILED:   message = "Failed to encode video."; break;
        case MSERR_OPEN_FILE_FAILED:  message = "Failed to open file."; break;
    }
    return RetInfo(err, message);
}
```

**Engine层返回精确码**：
```cpp
FALSE_RETURN_V_MSG_E(ret == Status::OK, MSERR_VID_ENC_FAILED, "video encoder failed");
```

### 第3步：验证修改范围

```powershell
git status --short
git diff --stat
git diff <file> | rg "MSERR_"
```

### 第4步：编译测试

构建并验证修改正确生效。

## 决策检查清单

**修改前**：统计覆盖场景数 → 确认只改核心模块 → 追溯完整链路 → 检查底层码是否精确 → 检查NAPI层映射逻辑

**修改中**：不猜测原因 → 只说实际错误 → 保持已知场景原映射

**修改后**：git diff 确认范围 → 编译验证 → 测试验证

## 错误码速查

### API9 错误码（JS层）

| 码 | 常量 | 含义 |
|----|------|------|
| 5400102 | MSERR_EXT_API9_INVALID_PARAMETER | 参数无效 |
| 5400103 | MSERR_EXT_API9_IO | IO错误 |
| 5400104 | MSERR_EXT_API9_SERVICE_FATAL_ERROR | 服务致命 |
| 5400105 | MSERR_EXT_API9_AUDIO_INTERRUPTED | 音频中断 |
| 5400106 | MSERR_EXT_API9_NO_MEMORY | 内存不足 |
| 5400107 | MSERR_EXT_API9_OPERATE_NOT_PERMIT | 操作不允许 |
| 5400108 | MSERR_EXT_API9_TIMEOUT | 超时 |

### 内部错误码（底层）

| 常量 | 含义 |
|------|------|
| MSERR_VID_ENC_FAILED | 视频编码失败 |
| MSERR_AUD_ENC_FAILED | 音频编码失败 |
| MSERR_AUD_RENDER_FAILED | 音频渲染失败 |
| MSERR_VID_DEC_FAILED | 视频解码失败 |
| MSERR_OPEN_FILE_FAILED | 文件打开失败 |
| MSERR_MUXER_FAILED | 封装失败 |
| MSERR_DEMUXER_FAILED | 解封装失败 |

## 关键文件路径

| 层 | 文件 |
|----|------|
| NAPI | `frameworks/js/avrecorder/avrecorder_napi.cpp` |
| Callback | `frameworks/js/avrecorder/avrecorder_callback.cpp` |
| Engine | `services/engine/histreamer/recorder/hirecorder_impl.cpp` |
| Server | `services/services/recorder/server/recorder_server.cpp` |
| 错误码定义 | `interfaces/inner_api/native/media_errors.h` |
| Filter (av_codec) | `services/media_engine/filters/` 下各 filter cpp |

## 错误码映射表模板

| Filter层码 | Engine层处理 | NAPI层映射 | JS层码 | JS层消息 |
|---|---|---|---|---|
| `Status::ERROR_AUDIO_INTERRUPT` | `MSERR_AUD_INTERRUPT` | 保持原映射 | `5400105` | "Record failed by audio interrupt." |
| `MSERR_VID_ENC_FAILED` | 保持 | 精细化 | `5400103` | "Failed to encode video." |
| `MSERR_OPEN_FILE_FAILED` | 保持 | 精细化 | `5400103` | "Failed to open file." |
# net_downloader

下载器核心模块，负责单文件/多文件 HTTP 下载的状态机管理、网络连接、进度上报和错误处理。

## 文件清单

| 文件 | 职责 |
|------|------|
| `downloader.h` | 公共接口：`Downloader` 抽象类、`DownloadCallback`、枚举、`DownloaderFactory` |
| `downloader_impl.h/cpp` | `Downloader` 实现：双消息队列、任务调度、状态管理 |
| `download_task.h/cpp` | 单任务下载：网络线程、状态转换、Pause/Cancel 超时处理、416 识别 |
| `download_network_client.h/cpp` | 网络客户端：HTTP 请求、断点续传、416 处理、ForceClose |
| `message_queue.h/cpp` | 消息队列：线程安全 FIFO、代际计数器、优先丢弃 |
| `network_client_agent.h/cpp` | 动态加载网络库：dlopen/dlsym 封装、单例管理 |
| `downloader_factory.cpp` | `DownloaderFactory::CreateDownloader()` 实现 |

## 枚举与类型

### DownloadState（状态机）

```
DOWNLOAD_IDLE → DOWNLOAD_PREPARING → DOWNLOAD_RUNNING
                                         ↓
              ┌──────────────────────────┤
              ↓              ↓           ↓
     DOWNLOAD_PAUSING  DOWNLOAD_CANCELING  (正常完成)
         ↓                 ↓
   DOWNLOAD_PAUSED   DOWNLOAD_CANCELED
         ↓                 ↓
   DOWNLOAD_RESUMING  (终态)
         ↓
   DOWNLOAD_RUNNING (重新运行)
```

| 状态 | 含义 | 可接受的转移来源 |
|------|------|----------------|
| IDLE | 初始/可启动 | — |
| PREPARING | 正在启动 | IDLE, COMPLETED |
| RUNNING | 下载中 | PREPARING, RESUMING |
| PAUSING | 暂停中（等待线程退出） | RUNNING |
| PAUSED | 已暂停 | PAUSING |
| RESUMING | 恢复中（等待 join 旧线程） | PAUSED |
| CANCELING | 取消中（等待线程退出） | RUNNING |
| COMPLETED | 下载完成 | RUNNING |
| FAILED | 下载失败 | RUNNING, PAUSING, CANCELING |
| CANCELED | 已取消 | RUNNING, CANCELING, PAUSED |

### DownloadErrorType / DownloadErrorCode

| ErrorType | 含义 |
|-----------|------|
| DOWNLOAD_ERROR_NONE | 无错误 |
| DOWNLOAD_ERROR_NETWORK | 网络错误 |
| DOWNLOAD_ERROR_FILE_IO | 文件 I/O 错误 |
| DOWNLOAD_ERROR_INVALID_URL | URL 无效 |
| DOWNLOAD_ERROR_INTERNAL | 内部错误 |

ErrorCode 包括 `DOWNLOAD_RET_OK(0)` 和负值错误码。curl 网络错误码列表：`{6, 7, 35, 55, 56}`（CURLE_COULDNT_RESOLVE_HOST, COULDNT_CONNECT, SSL_CONNECT_ERROR, SEND_ERROR, RECV_ERROR）。

### DownloadConfig

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `progressCallbackIntervalMs` | 1000 | 进度回调间隔 |
| `timeoutMs` | 60000 | 请求超时 |
| `retryCount` | 3 | 重试次数 |
| `bufferSize` | 8192 | 缓冲区大小 |
| `allowWifi` | true | 允许 WiFi 下载 |
| `allowMobileData` | false | 允许蜂窝下载 |

## 接口说明

### Downloader（公共接口）

调用方通过 `DownloaderFactory::CreateDownloader()` 获取实例。

```cpp
// 配置（Start 前调用）
SetUrl(url)              // 设置下载 URL
SetOutputPath(path)      // 设置输出文件路径
SetHeader(header)        // 设置 HTTP 请求头
SetConfig(config)        // 设置下载配置
AddFileTask(url, path, config)  // 添加多文件任务到队列
SetDownloadCallback(cb)  // 设置回调

// 生命周期
Start()   // 启动下载（IDLE/COMPLETED → PREPARING → RUNNING）
Pause()   // 暂停（RUNNING → PAUSING → PAUSED）
Resume()  // 恢复（PAUSED → RESUMING → RUNNING）
Cancel()  // 取消（RUNNING/PAUSED → CANCELING/CANCELED）
Release() // 释放资源

// 查询
GetState()           // 当前状态
GetProgress(progress) // 下载进度
GetCurrentFilePath() // 当前下载文件路径
GetDownloaderId()    // 下载器唯一 ID
```

### DownloadCallback（回调接口）

回调在 `messageQueue_` 线程触发（非下载线程、非调用线程）。

```cpp
OnStateChanged(downloaderId, state)      // 状态变化（不含 FAILED，FAILED 通过 OnFailed 上报）
OnCompleted(downloaderId, downloadedSize) // 下载完成
OnFailed(downloaderId, errorType, errorCode, errorMsg)  // 下载失败
OnProgress(downloaderId, progress)        // 进度更新
OnFileCompleted(downloaderId, url, fileSize)  // 单文件完成
```

### DownloadTaskCallback（内部回调接口）

`DownloadTask` 的回调接口，由 `DownloaderImpl` 实现。回调在下载线程（`workerThread_`）触发。

```cpp
OnStateChanged(state)              // DownloadTask 状态变化
OnCompleted(downloadedSize)        // 单任务完成
OnFailed(errorType, errorCode, errorMsg)  // 单任务失败
OnProgress(progress)               // 进度更新
```

## 调用约定

### 线程模型

DownloaderImpl 内部使用 **三个线程**：

| 线程 | 创建者 | 职责 |
|------|--------|------|
| `messageQueue_` 线程 | `StartMessageQueue()` | 处理对外回调（OnStateChanged/OnCompleted/OnFailed/OnProgress） |
| `schedulerQueue_` 线程 | `StartSchedulerQueue()` | 内部任务调度（HandleTaskCompleted/HandleTaskFailed/HandleTaskNetChanged/HandleTaskCanceled） |
| `workerThread_`（DownloadTask） | `DownloadTask::Start()/Resume()` | 实际网络下载（curl_easy_perform 等效操作） |

### 锁层次

```
DownloaderImpl::mutex_          — 保护 DownloaderImpl 状态转换（Pause/Resume/Cancel/Start 互斥）
DownloaderImpl::taskMutex_      — 保护 task_ 和 pendingTaskToRelease_
DownloaderImpl::queueMutex_     — 保护 taskQueue_
DownloaderImpl::progressMutex_  — 保护 progress_

DownloadTask::stateMutex_       — 保护 state_ 状态转换 + finishCv_ 条件变量
DownloadTask::clientMutex_      — 保护 networkClient_

NetworkClient::pauseMutex_      — 保护 paused_ 标志
NetworkClient::clientMutex_     — 保护 clientImpl_
```

锁序约定：`mutex_` → `taskMutex_`（不可反向）。

### Pause/Cancel 超时与 ForceClose

`DownloadTask::Pause()` 和 `Cancel()` 使用两阶段等待：

```
阶段 1: wait_for(PAUSE_TIMEOUT_SECONDS=1s)  — 等待 PauseDownload/Cancel 的优雅停止
  └─ 超时 → 阶段 2
阶段 2: ForceClose() + wait_for(FORCE_CLOSE_WAIT_SECONDS=1s)
  └─ ForceClose 强制中断网络连接
  └─ 释放 stateMutex_（wait_for 语义），下载线程进入 CheckDownloadResult
  └─ CheckDownloadResult 看到 PAUSING/CANCELING → 设 PAUSED/CANCELED → NotifyFinish
  └─ 唤醒阶段 2 的 wait_for → 返回 OK

阶段 2 也超时（兜底）: state_ = DOWNLOAD_FAILED
```

ForceClose 依赖生产环境自研网络库的安全中断能力。curl 参考实现中 `Close(true)` 需持有 `mutex_`，无法中断运行中的 `curl_easy_perform`；生产环境无此限制。

### 416 无 Content-Range 的文件完成识别

`NetworkClient::Handle416WithoutContentRange` 始终报失败（`requestSuccess=false` + `errorCallback_(416)`）。
识别"文件已完全下载"在 `DownloadTask::Run()` 中完成，在 `CheckDownloadResult` 调用前：

```cpp
if (!success && lastErrorCode_ == 416) {
    int64_t localSize = GetFileSize(outputPath_);
    if (localSize > 0) {
        success = true;  // 416 on resume → 文件已完整
    }
}
```

识别依据：请求 `Range: bytes=startPos-`，服务端返回 416 → 本地文件 ≥ 服务端文件 → 已完整。
`GetFileSize` 检查磁盘实际大小（ground truth），不依赖 `resumePos_` 或 `totalSize_`（冗余状态）。

### 消息队列代际计数器

`MessageQueue` 使用 `generation_` 原子计数器防止 `Stop()` 后旧线程不退出：

```cpp
void Run(uint64_t myGeneration) {
    while (running_.load()) {
        // 取消息前检查 generation
        if (myGeneration != generation_.load()) return;
        // ...
    }
}
```

`Stop()` 时 `generation_++` 并 detach 自线程，新 `Start()` 创建新线程。`PostMessage` 优先丢弃 `MSG_PROGRESS` 防止积压。

### 网络错误码识别

`DownloaderImpl::OnFailed` 检查 `IsNetworkErrorCode(errorCode)` 判断是否为网络切换：

- 是 → `MSG_TASK_NET_CHANGE` → `HandleTaskNetChanged()` → 设 PAUSED + 尝试自动恢复
- 否 → `MSG_TASK_FAILED` → `HandleTaskFailed()` → 设 FAILED + 上报

网络错误码列表：`{6, 7, 35, 55, 56}`。

## 关键设计决策

1. **双消息队列**：`messageQueue_`（对外回调）和 `schedulerQueue_`（内部调度）分离，避免回调阻塞影响调度
2. **Pause/Cancel 超时两阶段**：先优雅等待，超时后 ForceClose 强制中断，保证状态正确转换
3. **416 识别在 DownloadTask 层**：client 层始终报失败，DownloadTask 在状态决策前用磁盘文件大小交叉验证
4. **DownloadTask::OnStateChanged 过滤**：`DOWNLOAD_FAILED` 不向上传播 `NotifyStateChanged`（仅 `RUNNING/PAUSED/CANCELED` 传播），FAILED 通过 `OnFailed` 独立上报
5. **DownloaderImpl::Cancel 先设 CANCELED**：无论 task->Cancel() 成功与否，DownloaderImpl 状态已为 CANCELED，避免状态不一致

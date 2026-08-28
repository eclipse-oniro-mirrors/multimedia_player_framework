# net_downloader

下载器核心模块，负责单文件/多文件 HTTP 下载的状态机管理、网络连接、进度上报和错误处理。

## 文件清单

| 文件 | 职责 |
|------|------|
| `downloader.h` | 公共接口：`Downloader` 抽象类、`DownloadCallback`、枚举、`DownloaderFactory` |
| `downloader_impl.h/cpp` | `Downloader` 实现：双消息队列、任务调度、状态管理 |
| `download_task.h/cpp` | 单任务下载：网络线程、状态转换、Pause/Cancel 超时处理 |
| `download_network_client.h/cpp` | 网络客户端：HTTP 请求、断点续传、416 处理与完成识别、ForceClose |
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
| PAUSED | 已暂停 | PAUSING, RUNNING（网络连接错误） |
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

ErrorCode 包括 `DOWNLOAD_RET_OK(0)` 和负值错误码。curl 网络连接错误码列表：`{6, 7, 35, 55, 56}`（CURLE_COULDNT_RESOLVE_HOST, COULDNT_CONNECT, SSL_CONNECT_ERROR, SEND_ERROR, RECV_ERROR）。定义为 `HTTP_NETWORK_CONNECTION_ERROR_CODES` 常量数组，通过 `IsNetworkConnectionError(code)` 判断，两者均定义在 `download_network_client.h` 中。

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

`NetworkClient::Handle416WithoutContentRange` 在 NetworkClient 层直接判定完成，与带 Content-Range 匹配成功的路径（`CompareAndSetDownloadResult`）对齐：

```cpp
void NetworkClient::Handle416WithoutContentRange()
{
    if (startPos_ > 0) {
        ctx_->requestSuccess.store(true);   // 416 on resume → 已完整
        ctx_->totalSize.store(startPos_);
    } else {
        ctx_->requestSuccess.store(false);  // 首请求 416 不可能是完成
        errorCallback_(DOWNLOAD_ERROR_NETWORK, 416);
    }
}
```

识别依据：续传请求 `Range: bytes=startPos-`，服务端返回 416 表示 `startPos ≥ 资源总大小` → 本地已下完。`startPos_` 由 `SetOutputPath` 经 `fstat` 从磁盘读得（本次请求的实时值，非 `resumePos_`/`totalSize_` 那种冗余内存状态），且该路径无字节写盘、磁盘值不会漂移，故 416-on-resume 的 HTTP 语义已蕴含 `local ≥ server total`，无需在 DownloadTask 再做磁盘交叉验证。

`DownloadTask::Run()` 仅据 `client->IsRequestSuccess()` 决策，无 416 特判。四个 416 子分支全部在 NetworkClient 收敛：

| 分支 | requestSuccess | 结果 |
|------|----|----|
| 带 Content-Range 且 total==startPos | true | 完成（既有） |
| 带 Content-Range 且 total!=startPos | false | 失败（文件确实不完整） |
| Content-Range 格式错 | false | 失败 |
| 无 Content-Range 且 startPos>0 | true | 完成（本节） |
| 无 Content-Range 且 startPos==0 | false | 失败（首请求不可能完成） |

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

### 网络连接错误处理

网络连接错误（curl 6/7/35/55/56）采用**三层统一设为 PAUSED**策略，恢复由 `av_downloader_manager` 的 `OnNetworkChanged` 回调事件驱动：

```
DownloadTask::CheckDownloadResult(!success && IsNetworkConnectionError(lastErrorCode_))
  → state_ = DOWNLOAD_PAUSED + resumePos_ 保存
  → OnStateChanged(DOWNLOAD_PAUSED)          ← Task 层
  → OnFailed(networkErrorCode)
    → DownloaderImpl::OnFailed
      → IsNetworkConnectionError(errorCode)
      → state_ = DOWNLOAD_PAUSED + NotifyStateChanged  ← Impl 层
      → return（不发 MSG_TASK_NET_CHANGE，不发 MSG_TASK_FAILED）
```

恢复路径（事件驱动，非点查询）：

```
网络恢复 → NetConnCallbackImpl::NetAvailable(newType)
  → NetworkUtils::NotifyCallback(newType)
  → av_downloader_manager::OnNetworkChanged(newType)
    → IsNetworkAllowDownload(newType) → OnNetworkRestored()
      → 所有 PAUSED 任务 → 入队 QUEUED → PostMessage(MSG_PROCESS_NEXT_TASK)
      → ProcessNextPendingTask → downloader->Resume()
        → DownloadTask::Resume() → state_ == DOWNLOAD_PAUSED ✓ → 新 worker 线程
        → InitClient + ExecuteDownload → SetOutputPath(fstat 断点续传)
```

`HandleTaskNetChanged` 保留原始逻辑但不再被触发（`OnFailed` 不再发送 `MSG_TASK_NET_CHANGE`）。

## 关键设计决策

1. **双消息队列**：`messageQueue_`（对外回调）和 `schedulerQueue_`（内部调度）分离，避免回调阻塞影响调度
2. **Pause/Cancel 超时两阶段**：先优雅等待，超时后 ForceClose 强制中断，保证状态正确转换
3. **416 全部在 NetworkClient 层处理**：四个 416 子分支在 NetworkClient 收敛；DownloadTask 仅据 `IsRequestSuccess()` 决策，无 416 特判
4. **网络连接错误设 PAUSED 而非 FAILED**：`CheckDownloadResult` 通过 `IsNetworkConnectionError` 判断网络连接错误码，设 `DOWNLOAD_PAUSED`（可恢复）而非 `DOWNLOAD_FAILED`（终态）。`OnStateChanged(PAUSED)` 正常向上传播，由上层 `OnNetworkChanged` 回调在网络恢复时拉起 `Resume`。非网络错误仍为 `FAILED`，仅通过 `OnFailed` 独立上报
5. **DownloaderImpl::Cancel 先设 CANCELED**：无论 task->Cancel() 成功与否，DownloaderImpl 状态已为 CANCELED，避免状态不一致
6. **写盘用裸 `write()` 而非 stdio**：`WriteData` 用 `write(outputFd, ...)` 直接写内核 page cache。`av_downloader_manager` 的协议嗅探会在下载过程中用独立读 fd 重新打开本文件读取头部，依赖"`write()` 返回即对其他读端可见"的常规文件语义。改用 `FILE*`/`fwrite` 须先 `fflush`，否则嗅探读端读不到未刷新字节。`fsync` 与此无关（持久性，非可见性）。

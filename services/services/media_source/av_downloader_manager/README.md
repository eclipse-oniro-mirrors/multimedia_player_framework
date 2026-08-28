# av_downloader_manager

媒体下载管理器，管理多个下载任务的生命周期、并发调度、网络监听、协议嗅探和缓存映射。

## 文件清单

| 文件 | 职责 |
|------|------|
| `av_downloader_manager_impl.h` | 实现头文件：数据结构、`DownloadTaskCallback`、`AVDownloaderManagerImpl` |
| `av_downloader_manager.cpp` | 实现：任务调度、网络监听、状态上报、文件解析、映射生成 |
| `source_parse_agent.h/cpp` | 媒体源解析代理：协议嗅探、流资源解析 |
| `http_source_plugin_stream_resource_parser.h` | 流资源解析器接口 |
| `http_source_plugin_stream_protocol_sniffer.h` | 流协议嗅探器接口 |

公共接口定义在 `interfaces/inner_api/native/av_downloader_manager.h`。

## 枚举与类型

### AVDownloadTaskState（任务状态）

```
INIT → QUEUED → RUNNING → COMPLETED
                 ↓
              PAUSED ←→ QUEUED（网络恢复重入队）
                 ↓
             REMOVING → (移除)
                 
             ERROR（终态）
```

| 状态 | 含义 |
|------|------|
| INIT | 初始 |
| QUEUED | 在队列中等待（active < MAX_DOWNLOADER_COUNT=3） |
| RUNNING | 下载中 |
| COMPLETED | 全部文件下载完成 |
| PAUSED | 已暂停（可 Resume） |
| REMOVING | 正在移除 |
| ERROR | 下载失败 |

### DownloadState → AVDownloadTaskState 映射

| DownloadState | AVDownloadTaskState |
|-------------|---------------------|
| DOWNLOAD_IDLE | INIT |
| DOWNLOAD_PREPARING | QUEUED |
| DOWNLOAD_RUNNING | RUNNING |
| DOWNLOAD_PAUSED | PAUSED |
| DOWNLOAD_COMPLETED | COMPLETED |
| DOWNLOAD_FAILED | ERROR |
| DOWNLOAD_CANCELED | REMOVING |

### 数据结构

#### DownloadFileInfo

```cpp
struct DownloadFileInfo {
    std::string url;         // 文件 URL
    std::string filePath;    // 本地存储路径
    bool downloaded;         // 是否已下载
    bool needParse;          // 是否需要解析（HLS/DASH 子播放列表）
    uint64_t fileSize;       // 文件大小
};
```

#### AVDownloadTaskInfo

```cpp
struct AVDownloadTaskInfo {
    std::string taskId;           // downloader 的 id
    std::string url;              // 根 URL
    std::string cacheDir;         // 缓存根路径
    std::string currentFilePath;  // 当前下载文件路径
    AVDownloadTaskState state;    // 任务状态
    double progress;              // 进度 0.0~1.0
    int32_t errorCode;
    std::string errorMsg;
    bool protocolSniffed;         // 是否已嗅探协议
    bool parseCompleted;          // 解析是否完成
    StreamProtocolType detectedProtocol;  // HTTP/HLS/DASH
    std::vector<DownloadFileInfo> fileList;  // 所有文件（保持顺序）
    PlayStrategy strategy;
    TrackSelectionFilter filter;
    bool mappingFileCreated;
};
```

## 接口说明

### AVDownloaderManager（公共接口）

```cpp
// 配置
SetAllowCellularAccess(bool allow)    // 允许蜂窝下载
SetRequestTimeout(int32_t timeoutMs)  // 请求超时

// 任务管理
AddDownloadTask(source)    → taskId  // 添加下载任务
RemoveDownloadTask(taskId)           // 移除任务（Cancel + Release + 清理）
PauseDownloadTask(taskId)            // 暂停任务
ResumeDownloadTask(taskId)           // 恢复任务

// 查询
GetDownloadTasks()         → vector<taskId>
GetTaskCacheDirectory(taskId) → path
GetTaskStatus(taskId)      → AVDownloadTaskState
GetTaskProgress(taskId)    → double

// 回调
SetManagerCallback(callback)  // 状态/进度回调

// 生命周期
Release()
```

### AVDownloaderManagerCallback（回调接口）

回调在 `messageQueue_` 线程触发。

```cpp
OnStatusChange(taskId, state)     // 状态变化
OnProgressChange(taskId, progress) // 进度变化
```

### DownloadTaskCallback（内部回调，连接 DownloaderImpl）

`DownloadTaskCallback` 继承 `MediaDownload::DownloadCallback`，作为 `DownloaderImpl` 的回调目标。

```cpp
OnStateChanged(downloaderId, state)     // DownloaderImpl 状态变化
OnCompleted(downloaderId, downloadedSize) // 下载完成（未嗅探则补嗅探；触发解析或映射生成）
OnFailed(downloaderId, errorType, errorCode, errorMsg)  // 下载失败
OnProgress(downloaderId, progress)       // 进度更新（达到嗅探阈值触发协议嗅探）
OnFileCompleted(downloaderId, url, fileSize)  // 单文件完成
```

## 调用约定

### 并发调度模型

最多 `MAX_DOWNLOADER_COUNT = 3` 个下载器同时运行。超出部分进入 `pendingTaskQueue_` 等待。

```
AddDownloadTask / ResumeDownloadTask / FindExistingTask / OnNetworkRestored
  └─ pendingTaskQueue_.push_back({url, taskId})
     └─ taskMap_[taskId].state = QUEUED
     └─ PostMessage(MSG_PROCESS_NEXT_TASK)

ProcessNextPendingTask（唯一出队启动点）
  └─ while (GetActiveCountLocked() < MAX && !queue.empty())
      ├─ DOWNLOAD_PAUSED → downloader->Resume()
      ├─ DOWNLOAD_IDLE   → 初始化 + downloader->Start()
      └─ 其他 → continue（跳过）
```

循环内无 `break`，单次调用可启动多个任务直到 `GetActiveCountLocked() >= MAX`。这保证 `OnNetworkRestored` 后并发恢复到 MAX 而非退化为 1（仅发一条 `MSG_PROCESS_NEXT_TASK`）。

`GetActiveCountLocked()` 使用 `std::count_if` 实时统计 RUNNING 状态的任务数（不维护计数器变量）。

### 统一队列调度

所有需要启动任务的入口都走相同的路径：
1. 入队 `pendingTaskQueue_`
2. 设状态 `QUEUED`
3. `PostMessage(MSG_PROCESS_NEXT_TASK)`

`ProcessNextPendingTask` 是唯一的出队启动点，保证：
- 不会有多个入口同时启动下载器
- active count 检查在同一锁内完成

### 锁层次

```
mapMutex_    — 保护 taskMap_、downloaderMap_、pendingTaskQueue_ 的所有操作
cbMutex_     — 保护 callback_（状态/进度上报时持有）
```

**锁序约定**：`mapMutex_` → `cbMutex_`（`NotifyStatusChangeLocked` 内部先写 taskMap_ 再锁 cbMutex_）。不可反向。

`NotifyStatusChange`（非 Locked 版本）**不持有 mapMutex_**，在 messageQueue 线程调用，存在与 `OnNetworkLost`（持有 mapMutex_）的数据竞争。已知约束，状态值相同时无实际危害。

### 网络监听

```
StartNetworkListening()
  └─ NetworkUtils::RegisterNetworkChangeCallback(OnNetworkChanged)

OnNetworkChanged(newType)
  ├─ IsNetworkAllowDownload(newType) → OnNetworkRestored()
  └─ 否则 → OnNetworkLost()

OnNetworkRestored()
  └─ networkAvailable 隐含恢复
  └─ 所有 PAUSED 任务 → 入队 QUEUED → PostMessage(MSG_PROCESS_NEXT_TASK)

OnNetworkLost()
  ├─ QUEUED 任务 → 移出 pendingTaskQueue_ → NotifyStatusChangeLocked(PAUSED)
  └─ RUNNING 任务 → downloader->Pause() → NotifyStatusChangeLocked(PAUSED)
```

`IsNetworkAllowDownload` 判定规则：
- `NET_CONN_NONE` / `NET_CONN_UNKNOWN` → 不允许
- `NET_CONN_WIFI` → 允许
- `NET_CONN_CELLULAR` → 仅当 `allowCellularAccess_` 为 true 时允许

### OnFailed 网络状态检查

网络连接错误码（curl 6/7/35/55/56）在 `DownloaderImpl::OnFailed` 层已设 `DOWNLOAD_PAUSED` 并返回，**不进入** `av_downloader_manager::DownloadTaskCallback::OnFailed`。此处网络检查仅覆盖非网络错误码发生时网络恰好已断开的场景：

```cpp
if (!manager->IsNetworkAllowDownload(manager->GetNetworkType())) {
    // 网络不可用 → 失败可能由网络引起 → 设 PAUSED，不释放 downloader
    NotifyStatusChangeLocked(taskId, PAUSED);
    return;
}
// 网络正常 → 真正的非网络错误 → 设 ERROR + 释放 + 调度下一个
```

### Pause/Cancel 重试机制

`RemoveDownloadTask` 和 `PauseDownloadTask` 在底层 `downloader->Pause()/Cancel()` 可能遇到 HLS 分片切换导致的状态不匹配。使用 `RetryWithDeadline` 重试：

```cpp
RetryWithDeadline(downloader, []() { return downloader->Pause(); })
  └─ PAUSE_RETRY_TIMEOUT = 200ms, PAUSE_RETRY_INTERVAL = 10ms
  └─ 每 10ms 重试一次，最多 200ms
```

### RemoveDownloadTask 状态保护

```
RemoveDownloadTask:
  1. 设 taskMap_[taskId].state = REMOVING（持 mapMutex_）
  2. downloader->Cancel() + Release()（在 mapMutex_ 外执行，避免持锁等待网络操作）
  3. erase taskMap_[taskId], downloaderMap_[taskId]（持 mapMutex_）
  4. 若 oldState == RUNNING/QUEUED → PostMessage(MSG_PROCESS_NEXT_TASK)
```

REMOVING 状态防止其他入口（OnNetworkRestored、ProcessNextPendingTask）操作正在移除的任务。

### 协议嗅探与文件解析流程

```
OnProgress（首次达到嗅探阈值）
  └─ SniffStreamProtocol → SniffProtocolFromFile → 读取文件头部 → 检测 HTTP/HLS/DASH
     └─ HLS/DASH → fileList[0].needParse = true

OnCompleted（单文件下载完成）
  ├─ !protocolSniffed → SniffProtocolFromFile（完成时补嗅探，见下）
  ├─ 无需解析 → GenerateMappingFile + ProcessDownloadFinish
  └─ 需解析 → ParseFiles → SubmitRemainingTasks → Start()
```

### 续传重加完整 m3u8 的完成时补嗅探

续传重加场景下根 m3u8 已完整落盘，下载以 416→完成收尾、本次会话下载 0 字节，运行时嗅探（`OnProgress`→`SniffStreamProtocol`，门控 `downloadedSize >= sniffSize`）不会触发，导致 `needParse` 保持 false、m3u8 不被解析、分片 URL 不被发现。

修复：`OnCompleted` 在 `!protocolSniffed` 时调用 `SniffProtocolFromFile` 从已完整落盘的根文件补嗅探，设置 `detectedProtocol`/`protocolSniffed`，对 HLS/DASH 置 `fileList.front().needParse = true`，使 m3u8 进入正常解析→提交分片流程。已下载分片随之经 `SubmitRemainingTasks` 提交并走 416→完成。`!protocolSniffed` 保证仅首次（根文件完成）补嗅探，分片完成时跳过。

`SniffProtocolFromFile` 是从 `SniffStreamProtocol` 抽出的复用内核（读文件→嗅探→设状态→按需 `GenerateMappingFile`），供运行时嗅探与完成时补嗅探共用。`ReadFileData` 已硬化为读 `min(sniffSize, fileSize)`，支持小于 sniffSize 的小 m3u8（既有缺陷：小文件 `readLen < readSize` 即返回 false 导致嗅探失败）。

**读端与写端的 page cache 可见性**：嗅探用独立读 fd 重新打开被下载中的文件读取头部，依赖写端 `write()` 返回即写入内核 page cache、对其他读端立即可见这一常规文件语义。写端（`net_downloader` 的 `NetworkClient::WriteData`）刻意用裸 `write()` 而非带缓冲 stdio（`FILE*`/`fwrite`），且 `downloadedSize` 在 `write()` 成功后才递增——故 `OnProgress` 见 `downloadedSize >= sniffSize` 时，对应字节必已在 page cache，读端必然读到。无需 `fflush`/`fsync`（前者排空用户态 stdio 缓冲，后者保证落盘持久性，均与跨 fd 可见性无关）。若写端改用 stdio，须先 `fflush`，否则嗅探读端将读不到未刷新字节。

### 映射文件生成

下载完成后生成 `cache_mapping.txt`（二进制格式）：
- Header: magic "DCMH" + version + entryCount + checksum
- PlaybackParam: 序列化的 URL + PlayStrategy + TrackSelectionFilter
- Entries: 每个文件的 URL hash + 相对路径 + 文件大小

## 关键设计决策

1. **统一队列调度**：所有启动入口都入队 + PostMessage，`ProcessNextPendingTask` 唯一出队，消除并发启动竞态
2. **`GetActiveCountLocked()` 实时统计**：不维护 active 计数器，用 `count_if` 实时查询，消除计数器与实际状态的同步问题
3. **OnFailed 网络检查**：下载失败时探测网络状态，网络不可用则设 PAUSED（可重试），网络正常则设 ERROR（真正失败）
4. **RemoveDownloadTask 设 REMOVING**：防止移除过程中其他入口操作正在移除的任务
5. **Pause/Cancel 在锁外执行**：`downloader->Pause()/Cancel()` 在 `mapMutex_` 外调用，避免持锁等待网络操作
6. **RetryWithDeadline 处理 HLS 分片切换**：Pause/Cancel 可能因状态不匹配失败，短时间重试可自愈
7. **ForceClose 在 DownloadTask 层**：Pause/Cancel 超时后强制中断网络连接，保证状态正确转换（详见 net_downloader/README.md）

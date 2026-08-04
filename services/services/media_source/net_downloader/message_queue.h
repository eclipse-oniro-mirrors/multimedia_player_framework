/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MESSAGE_QUEUE_H
#define MESSAGE_QUEUE_H

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

#include "downloader.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

enum MessageType : int32_t {
    MSG_STATE_CHANGED = 0,
    MSG_COMPLETED,
    MSG_FAILED,
    MSG_PROGRESS,
    MSG_CANCEL,
    MSG_TASK_COMPLETED,     // 供内部任务调度使用
    MSG_TASK_FAILED,
    MSG_TASK_NET_CHANGE,
    MSG_TASK_CANCELED,
    MSG_RELEASE_DOWNLOADER,     // 释放downloader
    MSG_PROCESS_NEXT_TASK,      // 处理下个downloader
    MSG_FILE_COMPLETED,         // 单文件下载完成
};

struct Message {
    MessageType type;
    DownloadState state;
    DownloadProgress progress;
    DownloadErrorType errorType;
    int32_t errorCode;
    std::string errorMsg;
    int64_t downloadedSize;
    uint64_t downloaderId;
    std::string fileUrl;
};

class MessageQueue : public NoCopyable {
public:
    using MessageHandler = std::function<void(const Message &)>;

    MessageQueue();
    ~MessageQueue();

    // can be called only once within same MessageQueue instance
    void Start(MessageHandler handler);
    void Stop();
    void PostMessage(const Message &msg);

private:
    void Run(uint64_t myGeneration);

    std::deque<Message> queue_;
    std::mutex queueMutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_;
    std::thread thread_;
    MessageHandler handler_;
    std::mutex lifecycleMutex_;
    std::atomic<uint64_t> generation_{0};
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // MESSAGE_QUEUE_H
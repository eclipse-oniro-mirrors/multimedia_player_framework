/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <queue>
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
};

struct Message {
    MessageType type;
    DownloadState state;
    DownloadProgress progress;
    DownloadErrorType errorType;
    int32_t errorCode;
    std::string errorMsg;
    int64_t downloadedSize;
};

class MessageQueue : public NoCopyable {
public:
    using MessageHandler = std::function<void(const Message &)>;

    MessageQueue();
    ~MessageQueue();

    void Start(MessageHandler handler);
    void Stop();
    void PostMessage(const Message &msg);
    void ProcessMessages();

private:
    void Run();

    std::queue<Message> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_;
    std::thread thread_;
    MessageHandler handler_;
};

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

#endif // MESSAGE_QUEUE_H
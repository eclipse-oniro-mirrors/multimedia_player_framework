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

#include "message_queue.h"

#include "common/log.h"

#ifndef MEDIA_LOGD
#define MEDIA_LOGD MEDIA_LOG_D
#endif
#ifndef MEDIA_LOGI
#define MEDIA_LOGI MEDIA_LOG_I
#endif
#ifndef MEDIA_LOGW
#define MEDIA_LOGW MEDIA_LOG_W
#endif
#ifndef MEDIA_LOGE
#define MEDIA_LOGE MEDIA_LOG_E
#endif

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "NetDownloaderMessageQueue"};
constexpr int32_t MAX_QUEUE_SIZE = 100;
}

MessageQueue::MessageQueue()
    : running_(false),
      generation_(0)
{
    MEDIA_LOGI("MessageQueue created");
}

MessageQueue::~MessageQueue()
{
    Stop();
    MEDIA_LOGI("MessageQueue destroyed");
}

void MessageQueue::Start(MessageHandler handler)
{
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (running_.load()) {
        MEDIA_LOGW("MessageQueue already running");
        return;
    }

    handler_ = std::move(handler);
    auto gen = generation_.fetch_add(1) + 1;
    running_.store(true);
    thread_ = std::thread(&MessageQueue::Run, this, gen);

    MEDIA_LOGI("MessageQueue started, generation=%{public}" PRIu64, gen);
}

void MessageQueue::Stop()
{
    std::thread localThread;
    {
        std::lock_guard<std::mutex> lock(lifecycleMutex_);
        if (running_.load()) {
            running_.store(false);
            generation_.fetch_add(1);
            cv_.notify_all();
        }
        localThread = std::move(thread_);
        {
            std::lock_guard<std::mutex> queueLock(queueMutex_);
            queue_.clear();
        }
    }

    if (localThread.joinable()) {
        if (std::this_thread::get_id() != localThread.get_id()) {
            localThread.join();
        } else {
            localThread.detach();
        }
    }

    MEDIA_LOGI("MessageQueue stopped");
}

void MessageQueue::PostMessage(const Message &msg)
{
    std::lock_guard<std::mutex> lock(queueMutex_);

    if (!running_.load()) {
        MEDIA_LOGW("PostMessage failed: queue not running, type=%{public}d", msg.type);
        return;
    }

    if (queue_.size() >= MAX_QUEUE_SIZE) {
        auto it = std::find_if(queue_.begin(), queue_.end(), [](const Message &m) {
            return m.type == MSG_PROGRESS;
        });
        if (it != queue_.end()) {
            MEDIA_LOGW("PostMessage: queue full, dropping MSG_PROGRESS, newMsg=%{public}d", msg.type);
            queue_.erase(it);
        } else {
            MEDIA_LOGW("PostMessage: queue full, no MSG_PROGRESS, dropping oldest type=%{public}d",
                queue_.front().type);
            queue_.pop_front();
        }
    }

    queue_.push_back(msg);
    cv_.notify_one();

    MEDIA_LOGI("PostMessage: type=%{public}d", msg.type);
}

void MessageQueue::Run(uint64_t myGeneration)
{
    MEDIA_LOGI("MessageQueue thread started, generation=%{public}" PRIu64, myGeneration);

    MessageHandler handler;
    {
        std::lock_guard<std::mutex> lock(lifecycleMutex_);
        handler = handler_;
    }

    while (running_.load() && generation_.load() == myGeneration) {
        Message msg;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            cv_.wait(lock, [this, myGeneration] {
                return !queue_.empty() || !running_.load() || generation_.load() != myGeneration;
            });

            if (!running_.load() || generation_.load() != myGeneration) {
                break;
            }

            if (queue_.empty()) {
                continue;
            }

            msg = queue_.front();
            queue_.pop_front();
        }

        if (handler) {
            MEDIA_LOGI("MessageQueue handle type=%{public}d", msg.type);
            handler(msg);
        }
    }

    MEDIA_LOGI("MessageQueue thread ended, generation=%{public}" PRIu64, myGeneration);
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
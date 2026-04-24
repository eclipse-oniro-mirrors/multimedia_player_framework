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

#include "message_queue.h"

#include "media_log.h"

namespace OHOS {
namespace Media {
namespace MediaDownload {

namespace {
constexpr HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MessageQueue"};
constexpr int32_t MAX_QUEUE_SIZE = 100;
}

MessageQueue::MessageQueue()
    : running_(false)
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
    if (running_.load()) {
        MEDIA_LOGW("MessageQueue already running");
        return;
    }
    
    handler_ = handler;
    running_.store(true);
    thread_ = std::thread(&MessageQueue::Run, this);
    
    MEDIA_LOGI("MessageQueue started");
}

void MessageQueue::Stop()
{
    if (!running_.load()) {
        return;
    }
    
    running_.store(false);
    cv_.notify_all();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        while (!queue_.empty()) {
            queue_.pop();
        }
    }
    
    MEDIA_LOGI("MessageQueue stopped");
}

void MessageQueue::PostMessage(const Message &msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!running_.load()) {
        MEDIA_LOGW("PostMessage failed: queue not running");
        return;
    }
    
    if (queue_.size() >= MAX_QUEUE_SIZE) {
        MEDIA_LOGW("PostMessage: queue full, dropping oldest message");
        queue_.pop();
    }
    
    queue_.push(msg);
    cv_.notify_one();
    
    MEDIA_LOGD("PostMessage: type=%{public}d", msg.type);
}

void MessageQueue::Run()
{
    MEDIA_LOGI("MessageQueue thread started");
    
    while (running_.load()) {
        Message msg;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] { return !queue_.empty() || !running_.load(); });
            
            if (!running_.load()) {
                break;
            }
            
            if (queue_.empty()) {
                continue;
            }
            
            msg = queue_.front();
            queue_.pop();
        }
        
        if (handler_ != nullptr) {
            handler_(msg);
        }
    }
    
    MEDIA_LOGI("MessageQueue thread ended");
}

void MessageQueue::ProcessMessages()
{
    while (running_.load()) {
        Message msg;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (queue_.empty()) {
                return;
            }
            msg = queue_.front();
            queue_.pop();
        }
        
        if (handler_ != nullptr) {
            handler_(msg);
        }
    }
}

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS
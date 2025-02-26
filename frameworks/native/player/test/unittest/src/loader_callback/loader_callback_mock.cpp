/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "loader_callback_mock.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "MockLoaderCallback" };
constexpr int32_t LOADING_ERROR_NO_RESOURCE = 2;
static std::atomic<int64_t> g_uuid = 1;
static const std::map<std::string, std::string> g_urlToLocalPath = {
    {"https://appimg.dbankcdn.com/appVideo/f59583660abd45bcb4fb9c3e3f1125a9.mp4", "/data/test/request.mp4"},
};
static const std::map<std::string, std::map<std::string, std::string>> g_urlToHeader = {
    {"https://appimg.dbankcdn.com/appVideo/f59583660abd45bcb4fb9c3e3f1125a9.mp4", {{"content-length", "9924003"}}},
};
}

namespace OHOS {
namespace Media {
MockLoaderCallback::MockLoaderCallback()
    : taskQue_("MockLoaderCallback")
{
    MEDIA_LOGD("MockLoaderCallback:0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    (void)taskQue_.Start();
}

MockLoaderCallback::~MockLoaderCallback()
{
    if (file_ != nullptr) {
        (void)fclose(file_);
        file_ = nullptr;
    }
    (void)taskQue_.Stop();
    MEDIA_LOGD("MockLoaderCallback:0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int64_t MockLoaderCallback::Open(std::shared_ptr<LoadingRequest> &request)
{
    MEDIA_LOGI("Open enter");
    int64_t uuid = g_uuid.fetch_add(1, std::memory_order_relaxed);
    requests_[uuid] = request;
    auto localPath = g_urlToLocalPath.find(request->GetUrl());
    if (localPath != g_urlToLocalPath.end()) {
        if (file_ != nullptr) {
            fclose(file_);
            file_ = nullptr;
        }
        file_ = fopen(localPath->second.c_str(), "rb+");
    }
    return uuid;
}

void MockLoaderCallback::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    MEDIA_LOGI("Read enter");
    auto request = requests_.find(uuid);
    if (request != requests_.end()) {
        // respond header
        auto task = std::make_shared<TaskHandler<void>>([=] {
            MEDIA_LOGI("task RespondHeader enter");
            auto header = g_urlToHeader.find(request->second->GetUrl());
            if (header == g_urlToHeader.end()) {
                MEDIA_LOGI("get header fail");
                (void)request->second->FinishLoading(uuid, LOADING_ERROR_NO_RESOURCE);
                return;
            }
            (void)request->second->RespondHeader(uuid, header->second, "");
        });
        (void)taskQue_.EnqueueTask(task);
        // respond data
        task = std::make_shared<TaskHandler<void>>([=] {
            MEDIA_LOGI("task RespondData enter");
            auto buffer = std::make_shared<AVSharedMemoryBase>(static_cast<int32_t>(requestedLength),
                AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
            if (buffer == nullptr || file_ == nullptr) {
                MEDIA_LOGI("get buffer fail");
                (void)request->second->FinishLoading(uuid, LOADING_ERROR_NO_RESOURCE);
                return;
            }
            buffer->Init();
            (void)fseek(file_, static_cast<long>(requestedOffset), SEEK_SET);
            size_t readRet = fread(buffer->GetBase(), static_cast<size_t>(requestedLength), 1, file_);
            if (ferror(file_) || readRet != 1) {
                MEDIA_LOGE("IO error, offest %{public}" PRId64 " length %{public}" PRId64 "readRet %{public}d",
                    requestedOffset, requestedLength, static_cast<int32_t>(readRet));
                (void)request->second->FinishLoading(uuid, LOADING_ERROR_NO_RESOURCE);
                return;
            }
            (void)request->second->RespondData(uuid, requestedOffset, buffer);
        });
        (void)taskQue_.EnqueueTask(task);
    } else {
        MEDIA_LOGI("read uuid fail");
    }
}

void MockLoaderCallback::Close(int64_t uuid)
{
    MEDIA_LOGI("Close enter");
    requests_.erase(uuid);
    if (file_ != nullptr) {
        fclose(file_);
        file_ = nullptr;
    }
}
} // namespace Media
} // namespace OHOS
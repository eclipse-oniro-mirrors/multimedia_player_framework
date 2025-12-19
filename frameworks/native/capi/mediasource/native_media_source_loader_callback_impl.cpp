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

#include "media_dfx.h"
#include "media_log.h"
#include "native_media_source_loader_callback_impl.h"
#include "native_media_source_loading_request_impl.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "NativeMediaSourceLoaderCallbackImpl"};
}

namespace OHOS {
namespace Media {

int64_t NativeOnSourceOpenedCallback::Open(std::shared_ptr<LoadingRequest> &request)
{
    CHECK_AND_RETURN_RET_LOG(callback_ != nullptr, -1, "opened callback is nullptr");

    Release();

    request_ = new (std::nothrow) MediaSourceLoadingRequestObject(request);
    CHECK_AND_RETURN_RET_LOG(request_ != nullptr, -1, "failed to create OH_AVMediaSourceLoadingRequest");

    return callback_(request_, userData_);
}

void NativeOnSourceOpenedCallback::Release()
{
    if (request_ != nullptr) {
        delete request_;
        request_ = nullptr;
    }
}

void NativeOnSourceReadCallback::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "read callback_ is nullptr");

    callback_(uuid, requestedOffset, requestedLength, userData_);
}

void NativeOnSourceClosedCallback::Close(int64_t uuid)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "close callback_ is nullptr");

    callback_(uuid, userData_);
}

int64_t MediaSourceLoaderCallback::Open(std::shared_ptr<LoadingRequest> &request)
{
    CHECK_AND_RETURN_RET_LOG(openedCallback_ != nullptr, -1, "open callback is nullptr");

    std::lock_guard<std::mutex> lock(mutex_);
    return openedCallback_->Open(request);
}

void MediaSourceLoaderCallback::Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength)
{
    CHECK_AND_RETURN_LOG(readCallback_ != nullptr, "read callback is nullptr");

    std::lock_guard<std::mutex> lock(mutex_);
    readCallback_->Read(uuid, requestedOffset, requestedLength);
}

void MediaSourceLoaderCallback::Close(int64_t uuid)
{
    CHECK_AND_RETURN_LOG(closeCallback_ != nullptr, "close callback is nullptr");

    std::lock_guard<std::mutex> lock(mutex_);
    closeCallback_->Close(uuid);
}

void MediaSourceLoaderCallback::SetSourceOpenCallback(NativeOnSourceOpenedCallback *callback)
{
    MEDIA_LOGD("Set Source Open Callback");
    std::lock_guard<std::mutex> lock(mutex_);
    openedCallback_ = std::shared_ptr<NativeOnSourceOpenedCallback>(callback);
}

void MediaSourceLoaderCallback::SetSourceReadCallback(NativeOnSourceReadCallback *callback)
{
    MEDIA_LOGD("Set Source Read Callback");
    std::lock_guard<std::mutex> lock(mutex_);
    readCallback_ = std::shared_ptr<NativeOnSourceReadCallback>(callback);
}

void MediaSourceLoaderCallback::SetSourceCloseCallback(NativeOnSourceClosedCallback *callback)
{
    MEDIA_LOGD("Set Source Close Callback");
    std::lock_guard<std::mutex> lock(mutex_);
    closeCallback_ = std::shared_ptr<NativeOnSourceClosedCallback>(callback);
}

void MediaSourceLoaderCallback::Release()
{
    MEDIA_LOGD("Release MediaSourceLoaderCallback");
    std::lock_guard<std::mutex> lock(mutex_);
    if (openedCallback_ != nullptr) {
        openedCallback_->Release();
    }
}

}
}

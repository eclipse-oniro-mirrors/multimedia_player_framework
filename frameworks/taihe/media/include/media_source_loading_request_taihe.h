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
#ifndef MEDIA_SOURCE_LOADING_REQUEST_TAIHE_H
#define MEDIA_SOURCE_LOADING_REQUEST_TAIHE_H

#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "media_ani_common.h"
#include "loading_request.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;
class MediaSourceLoadingRequestImpl {
public:
    MediaSourceLoadingRequestImpl(uint64_t requestId);
    string GetUrl();
    optional<map<string, string>> GetHeader();
    optional<int32_t> RespondData(double uuid, double offset, array_view<uint8_t> buffer);
    void RespondHeader(double uuid, optional_view<map<string, string>> header, optional_view<string> redirectUrl);
    void FinishLoading(double uuid, LoadingRequestError state);
    static ::ohos::multimedia::media::MediaSourceLoadingRequest CreateLoadingRequest(
        std::shared_ptr<OHOS::Media::LoadingRequest> request);
private:
    std::shared_ptr<OHOS::Media::LoadingRequest> request_;
};

class RequestContainer {
public:
    static RequestContainer &GetInstance()
    {
        static RequestContainer* inst = nullptr;
        static std::once_flag once;
        std::call_once(once, [&] { inst = new RequestContainer(); });
        return *inst;
    }

    bool IsEmpty()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return data_.empty();
    }

    void Insert(uint64_t key, std::shared_ptr<OHOS::Media::LoadingRequest> value)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto result = data_.insert({key, value});
        if (!result.second) {
            data_[key] = value;
        }
    }

    std::shared_ptr<OHOS::Media::LoadingRequest> Find(uint64_t key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = data_.find(key);
        if (it != data_.end()) {
            return it->second;
        }
        return nullptr;
    }

    void Erase(uint64_t key)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        data_.erase(key);
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        data_.clear();
    }
private:
    RequestContainer() = default;
    ~RequestContainer() = default;
    RequestContainer(const RequestContainer&) = delete;
    RequestContainer& operator=(const RequestContainer&) = delete;

    std::mutex mutex_;
    std::map<uint64_t, std::shared_ptr<OHOS::Media::LoadingRequest>> data_;
};
} // namespace ANI::Media
#endif // MEDIA_SOURCE_LOADING_REQUEST_TAIHE_H
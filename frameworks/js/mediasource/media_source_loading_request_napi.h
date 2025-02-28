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

#ifndef MEDIA_SOURCE_LOADING_REQUEST_NAPI_H
#define MEDIA_SOURCE_LOADING_REQUEST_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "common_napi.h"
#include "loading_request.h"

namespace OHOS {
namespace Media {

class MediaSourceLoadingRequestNapi {
public:
    __attribute__((visibility("default"))) static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateLoadingRequest(napi_env env, std::shared_ptr<LoadingRequest> request);
private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);
    /**
     * function RespondData(uuid:number, offset:number, buffer: ArrayBuffer): number;
     */
    static napi_value JsRespondData(napi_env env, napi_callback_info info);
    /**
     * function RespondHeader(uuid:number, header?: Record<string,string>, redirectUrl?: string): void;
     */
    static napi_value JsRespondHeader(napi_env env, napi_callback_info info);
    /**
     * function FinishLoading(uuid:number, state: LoadingRequestError): void;
     */
    static napi_value JsFinishLoading(napi_env env, napi_callback_info info);
    /**
     * url: string
     */
    static napi_value JsGetUrl(napi_env env, napi_callback_info info);
    /**
     * header?: Record<string, string>
     */
    static napi_value JsGetHeader(napi_env env, napi_callback_info info);

    MediaSourceLoadingRequestNapi();
    virtual ~MediaSourceLoadingRequestNapi();

    static MediaSourceLoadingRequestNapi* GetJsInstance(napi_env env, napi_callback_info info);
    static MediaSourceLoadingRequestNapi* GetJsInstanceWithParameter(napi_env env, napi_callback_info info,
        size_t &argc, napi_value *argv);

private:
    static thread_local napi_ref constructor_;
    napi_env env_ = nullptr;
    std::shared_ptr<LoadingRequest> request_;
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

    void Insert(uint64_t key, std::shared_ptr<LoadingRequest> value)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto result = data_.insert({key, value});
        if (!result.second) {
            data_[key] = value;
        }
    }

    std::shared_ptr<LoadingRequest> Find(uint64_t key)
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
    std::map<uint64_t, std::shared_ptr<LoadingRequest>> data_;
};
} // Media
} // OHOS
#endif // MEDIA_SOURCE_LOADING_REQUEST_NAPI_H
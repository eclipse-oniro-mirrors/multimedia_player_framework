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

#ifndef NATIVE_MEDIA_SOURCE_LOADER_CALLBACK_IMPL_H
#define NATIVE_MEDIA_SOURCE_LOADER_CALLBACK_IMPL_H

#include <mutex>

#include "avmedia_source.h"
#include "loading_request.h"
#include "native_player_magic.h"

namespace OHOS {
namespace Media {

class NativeOnSourceOpenedCallback {
public:
    explicit NativeOnSourceOpenedCallback(OH_AVMediaSourceLoaderOnSourceOpenedCallback callback, void *userData)
        : callback_(callback), userData_(userData) {};
    virtual ~NativeOnSourceOpenedCallback() = default;

    int64_t Open(std::shared_ptr<LoadingRequest> &request);
    void Release();

private:
    OH_AVMediaSourceLoadingRequest *request_ = nullptr;
    OH_AVMediaSourceLoaderOnSourceOpenedCallback callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeOnSourceReadCallback {
public:
    explicit NativeOnSourceReadCallback(OH_AVMediaSourceLoaderOnSourceReadCallback callback, void *userData)
        : callback_(callback), userData_(userData) {};
    virtual ~NativeOnSourceReadCallback() = default;

    void Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength);

private:
    OH_AVMediaSourceLoaderOnSourceReadCallback callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeOnSourceClosedCallback {
public:
    explicit NativeOnSourceClosedCallback(OH_AVMediaSourceLoaderOnSourceClosedCallback callback, void *userData)
        : callback_(callback), userData_(userData) {};
    virtual ~NativeOnSourceClosedCallback() = default;

    void Close(int64_t uuid);

private:
    OH_AVMediaSourceLoaderOnSourceClosedCallback callback_ = nullptr;
    void *userData_ = nullptr;
};

class MediaSourceLoaderCallback : public LoaderCallback, public NoCopyable {
public:
    explicit MediaSourceLoaderCallback() = default;
    virtual ~MediaSourceLoaderCallback() = default;

    int64_t Open(std::shared_ptr<LoadingRequest> &request) override;
    void Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength) override;
    void Close(int64_t uuid) override;
    void SetSourceOpenCallback(NativeOnSourceOpenedCallback *callback);
    void SetSourceReadCallback(NativeOnSourceReadCallback *callback);
    void SetSourceCloseCallback(NativeOnSourceClosedCallback *callback);
    void Release();

private:
    std::mutex mutex_;
    std::shared_ptr<NativeOnSourceOpenedCallback> openedCallback_ = nullptr;
    std::shared_ptr<NativeOnSourceReadCallback> readCallback_ = nullptr;
    std::shared_ptr<NativeOnSourceClosedCallback> closeCallback_ = nullptr;
};

struct AVMediaSourceLoader : public OH_AVMediaSourceLoader {
    explicit AVMediaSourceLoader(const std::shared_ptr<MediaSourceLoaderCallback> &callback)
        : callback_(callback) {}
    ~AVMediaSourceLoader() = default;

    const std::shared_ptr<MediaSourceLoaderCallback> callback_ = nullptr;
};

}
}

#endif // NATIVE_MEDIA_SOURCE_LOADER_CALLBACK_IMPL_H
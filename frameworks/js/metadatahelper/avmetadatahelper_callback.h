/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef AV_META_DATA_HELPER_CALLBACK_H
#define AV_META_DATA_HELPER_CALLBACK_H

#include <map>
#include <mutex>
#include "media_errors.h"
#include "common_napi.h"
#include "event_handler.h"
#include "avmetadatahelper.h"
#include "pixel_map.h"

namespace OHOS {
namespace Media {
using OnInfoFunc = std::function<void (const int32_t, const Format &)>;
namespace AVMetadataHelperState {
const std::string STATE_IDLE = "idle";
const std::string STATE_PREPARED = "prepared";
const std::string STATE_RELEASED = "released";
const std::string STATE_CALL_DONE = "callDone";
const std::string STATE_ERROR = "error";
}

namespace AVMetadataHelperEvent {
const std::string EVENT_STATE_CHANGE = "stateChange";
const std::string EVENT_ERROR = "error";
const std::string EVENT_PIXEL_COMPLETE = "onFrameFetched";
}

class AVMetadataHelperNotify {
public:
    AVMetadataHelperNotify() = default;
    virtual ~AVMetadataHelperNotify() = default;
    virtual void NotifyState(HelperStates state) = 0;
};

class AVMetadataHelperCallback : public HelperCallback {
public:
    explicit AVMetadataHelperCallback(napi_env env);
    AVMetadataHelperCallback(napi_env env, AVMetadataHelperNotify *listener);
    virtual ~AVMetadataHelperCallback();
    void OnError(int32_t errorCode, const std::string &errorMsg);
    void OnInfo(HelperOnInfoType type, int32_t extra, const Format &infoBody);
    void OnPixelComplete (HelperOnInfoType type,
                        const std::shared_ptr<AVBuffer> &reAvbuffer_,
                        const FrameInfo &info,
                        const PixelMapParams &param);
    void OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg);
    HelperStates GetCurrentState() const;
    void SaveCallbackReference(const std::string &name, std::shared_ptr<AutoRef> ref);
    void setHelper(const std::shared_ptr<AVMetadataHelper> &helper);
    void ClearCallbackReference();
    void ClearCallbackReference(const std::string &name);
    void Start();
    void Pause();
    void Release();
    void SendPixelCompleteCallback(const FrameInfo &info, const std::shared_ptr<PixelMap> &pixelMap);
private:
    enum FetchResult {
        FETCH_FAILED = 0,
        FETCH_SUCCEEDED = 1,
        FETCH_CANCELED = 2,
    };

    struct AVMetadataJsCallback {
        std::shared_ptr<AutoRef> autoRef;
        std::string callbackName = "OnFrameFetched";
        std::string errorMs;
        int32_t errorCode;
        int32_t reason = 1;
        std::string state = "unknown";
        std::shared_ptr<PixelMap> pixel_ = nullptr;
        FetchResult fetchResult;
        int64_t requestedTimeUs;
        int64_t actualTimeUs;
    };

    void OnJsPixelCompleteCallback(AVMetadataJsCallback *jsCb) const;
    void OnStateChangeCb(const int32_t extra, const Format &infoBody);
    std::shared_ptr<AVMetadataHelper> helper_ = nullptr;
    std::map<HelperOnInfoType, OnInfoFunc> onInfoFuncs_;
    std::mutex mutex_;
    napi_env env_ = nullptr;
    std::map<std::string, std::shared_ptr<AutoRef>> refMap_;
    AVMetadataHelperNotify *listener_ = nullptr;
    std::atomic<bool> isloaded_ = false;
    HelperStates state_ = HELPER_IDLE;
};
} // namespace Media
} // namespace OHOS
#endif // AV_META_DATA_HELPER_CALLBACK_H
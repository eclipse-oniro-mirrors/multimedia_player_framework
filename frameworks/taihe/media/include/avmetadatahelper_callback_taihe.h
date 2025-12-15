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
#ifndef AVMETADATAHELPER_CALLBACK_TAIHE_H
#define AVMETADATAHELPER_CALLBACK_TAIHE_H

#include <map>
#include <mutex>
#include "media_errors.h"
#include "media_ani_common.h"
#include "event_handler.h"
#include "pixel_map.h"
#include "avmetadatahelper.h"

namespace ANI {
namespace Media {

namespace AVMetadataHelperEvent {
const std::string EVENT_STATE_CHANGE = "stateChange";
const std::string EVENT_ERROR = "error";
const std::string EVENT_PIXEL_COMPLETE = "onFrameFetched";
}

class AVMetadataHelperCallback : public OHOS::Media::HelperCallback {
public:
    ~AVMetadataHelperCallback();
    void OnPixelComplete (OHOS::Media::HelperOnInfoType type,
                        const std::shared_ptr<OHOS::Media::AVBuffer> &reAvbuffer_,
                        const OHOS::Media::FrameInfo &info,
                        const OHOS::Media::PixelMapParams &param);
    void OnInfo(OHOS::Media::HelperOnInfoType type, int32_t extra, const OHOS::Media::Format &infoBody);
    void OnError(int32_t errorCode, const std::string &errorMsg);
    void SaveCallbackReference(const std::string &name, std::shared_ptr<AutoRef> ref);
    void setHelper(const std::shared_ptr<OHOS::Media::AVMetadataHelper> &helper);
    void SendPixelCompleteCallback(const OHOS::Media::FrameInfo &info,
        const std::shared_ptr<OHOS::Media::PixelMap> &pixelMap);

private:
    enum FetchResult {
        FETCH_FAILED = 0,
        FETCH_SUCCEEDED = 1,
        FETCH_CANCELLED = 2,
    };

    struct FrameInfo {
        int64_t requestedTimeUs;
        int64_t actualTimeUs;
        std::shared_ptr<OHOS::Media::PixelMap> pixel_ = nullptr;
        FetchResult fetchResult;
    };

    struct AVMetadataJsCallback {
        std::shared_ptr<AutoRef> autoRef;
        std::string callbackName = "OnFrameFetched";
        std::string errorMs;
        int32_t errorCode;
        int32_t reason = 1;
        std::string state = "unknown";
        std::shared_ptr<OHOS::Media::PixelMap> pixel_ = nullptr;
        FetchResult fetchResult;
        int64_t requestedTimeUs;
        int64_t actualTimeUs;
    };

    void OnJsPixelCompleteCallback(AVMetadataJsCallback *jsCb) const;
    std::shared_ptr<OHOS::Media::AVMetadataHelper> helper_ = nullptr;
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<AutoRef>> refMap_;
};
}
}
#endif // AVPLAYER_CALLBACK_TAIHE_H
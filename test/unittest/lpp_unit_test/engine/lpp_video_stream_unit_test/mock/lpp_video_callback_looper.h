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

#ifndef LPP_VIDEO_CALLBACK_LOOPER
#define LPP_VIDEO_CALLBACK_LOOPER

#include <gmock/gmock.h>
#include <list>
#include <utility>
#include "i_lpp_video_streamer.h"
#include "meta/any.h"

namespace OHOS {
namespace Media {
class LppVideoCallbackLooper : public std::enable_shared_from_this<LppVideoCallbackLooper> {
public:
    explicit LppVideoCallbackLooper(std::string lppVideoStreamerId)
    {
        (void) lppVideoStreamerId;
    }
    MOCK_METHOD(void, OnDataNeeded, (const int32_t maxBufferSize, const int32_t maxFrameNum));
    MOCK_METHOD(void, OnAnchorUpdateNeeded, (int64_t &anchorPts, int64_t &anchorClk));
    MOCK_METHOD(void, OnError, (const MediaServiceErrCode errCode, const std::string &errMsg));
    MOCK_METHOD(void, OnEos, ());
    MOCK_METHOD(void, OnRenderStarted, ());
    MOCK_METHOD(void, OnTargetArrived, (const int64_t targetPts, const bool isTimeout));
    MOCK_METHOD(void, OnFirstFrameReady, ());
    MOCK_METHOD(void, OnStreamChanged, (Format &format));
    MOCK_METHOD(void, Stop, ());
    MOCK_METHOD(void, Reset, ());
    MOCK_METHOD(void, StartWithLppVideoStreamerEngineObs, (const std::weak_ptr<ILppVideoStreamerEngineObs> &obs));
};
}  // namespace Media
}  // namespace OHOS
#endif  // LPP_VIDEO_CALLBACK_LOOPER
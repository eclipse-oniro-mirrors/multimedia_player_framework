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

#include <list>
#include <utility>
#include "osal/task/task.h"
#include "i_lpp_video_streamer.h"
#include "meta/any.h"
#include "osal/utils/steady_clock.h"
#include "osal/task/condition_variable.h"
#include "osal/task/mutex.h"

namespace OHOS {
namespace Media {

class LppVideoCallbackLooper : public ILppVideoStreamerEngineObs {
public:
    explicit LppVideoCallbackLooper(std::string lppVideoStreamerId);
    ~LppVideoCallbackLooper() override;

    void OnDataNeeded(const int32_t maxBufferSize, const int32_t maxFrameNum) override;
    bool OnAnchorUpdateNeeded(int64_t &anchorPts, int64_t &anchorClk) override;
    void OnError(const LppErrCode errCode, const std::string &errMsg) override;
    void OnEos() override;
    void OnRenderStarted() override;
    void OnTargetArrived(const int64_t targetPts, const bool isTimeout) override;
    void OnFirstFrameReady() override;
    void OnStreamChanged(Format &format) override;

    void Stop();
    void Reset();
    void StartWithLppVideoStreamerEngineObs(const std::weak_ptr<ILppVideoStreamerEngineObs> &obs);

private:
    std::string lppVideoStreamerId_ {};
    std::unique_ptr<OHOS::Media::Task> task_ {nullptr};
    std::weak_ptr<ILppVideoStreamerEngineObs> obs_{};
    bool taskStarted_{false};
};
}  // namespace Media
}  // namespace OHOS
#endif  // LPP_VIDEO_CALLBACK_LOOPER
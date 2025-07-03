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

#ifndef LPP_AUDIO_CALLBACK_LOOPER
#define LPP_AUDIO_CALLBACK_LOOPER

#include <list>
#include <utility>
#include "osal/task/task.h"
#include "i_lpp_audio_streamer.h"
#include "meta/any.h"
#include "osal/utils/steady_clock.h"
#include "osal/task/condition_variable.h"
#include "osal/task/mutex.h"
#include "lpp_common.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
class LppAudioCallbackLooper {
public:
    LppAudioCallbackLooper(std::string lppAudioStreamerId);
    ~LppAudioCallbackLooper();

    void OnDataNeeded(const int32_t maxBufferSize);
    void OnPositionUpdated(const int64_t currentPositionMs);
    void OnError(const MediaServiceErrCode errCode, const std::string &errMsg);
    void OnEos();
    void OnInterrupted(const int64_t forceType, const int64_t hint);
    void OnDeviceChanged(const int64_t reason);
    void Stop();
    void Reset();
    void SetEngine(std::weak_ptr<ILppAudioStreamerEngine> engine);
    void StartWithLppAudioStreamerEngineObs(const std::weak_ptr<ILppAudioStreamerEngineObs> &obs);
    void StartPositionUpdate();
    void StopPositionUpdate();

private:
    void DoPositionUpdate(int64_t positionUpdateIdx);
    int32_t GetCurrentPosition(int64_t &currentPosition);

    std::string lppAudioStreamerId_ {};
    std::unique_ptr<OHOS::Media::Task> task_ {nullptr};
    std::weak_ptr<ILppAudioStreamerEngineObs> obs_{};
    std::weak_ptr<ILppAudioStreamerEngine> engine_ {};
    std::atomic<int64_t> positionUpdateIdx_ {0};
};
}  // namespace Media
}  // namespace OHOS
#endif  // LPP_AUDIO_CALLBACK_LOOPER

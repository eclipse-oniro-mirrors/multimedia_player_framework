/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

#ifndef HISTREAMER_HIPLAYER_CALLBACKER_LOOPER_H
#define HISTREAMER_HIPLAYER_CALLBACKER_LOOPER_H

#include <list>
#include <utility>
#include "osal/task/task.h"
#include "i_player_engine.h"
#include "meta/any.h"
#include "osal/utils/steady_clock.h"
#include "osal/task/condition_variable.h"
#include "osal/task/mutex.h"

namespace OHOS {
namespace Media {
class HiPlayerCallbackLooper : public IPlayerEngineObs {
public:
    explicit HiPlayerCallbackLooper();
    ~HiPlayerCallbackLooper() override;

    bool IsStarted();

    void Stop();

    void StartWithPlayerEngineObs(const std::weak_ptr<IPlayerEngineObs>& obs);

    void SetPlayEngine(IPlayerEngine* engine, std::string playerId);

    void StartReportMediaProgress(int64_t updateIntervalMs = 1000);

    void StopReportMediaProgress();

    void ManualReportMediaProgressOnce();

    void OnError(PlayerErrorType errorType, int32_t errorCode) override;

    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody) override;

    void DoReportCompletedTime();
    void startCollectMaxAmplitude(int64_t updateIntervalMs);
    void StopCollectMaxAmplitude();

private:

    void DoReportMediaProgress();
    void DoReportInfo(const Any& info);
    void DoReportError(const Any& error);
    void DoCollectAmplitude();

    struct Event {
        Event(int32_t inWhat, int64_t inWhenMs, Any inAny): what(inWhat), whenMs(inWhenMs),
            detail(std::move(inAny)) {}
        int32_t what {0};
        int64_t whenMs {INT64_MAX};
        Any detail;
    };

    void LoopOnce(const std::shared_ptr<HiPlayerCallbackLooper::Event>& item);
    void Enqueue(const std::shared_ptr<Event>& event);

    std::unique_ptr<OHOS::Media::Task> task_;
    OHOS::Media::Mutex loopMutex_ {};
    bool taskStarted_ {false};
    IPlayerEngine* playerEngine_ {};
    std::weak_ptr<IPlayerEngineObs> obs_ {};
    bool reportMediaProgress_ {false};
    bool collectMaxAmplitude_ {false};
    bool isDropMediaProgress_ {false};
    int64_t reportProgressIntervalMs_ {100}; // default interval is 100 ms
    int64_t collectMaxAmplitudeIntervalMs_ {100}; // default interval is 100 ms
    std::vector<float> vMaxAmplitudeArray_ {};
};
}  // namespace Media
}  // namespace OHOS
#endif // HISTREAMER_HIPLAYER_CALLBACKER_LOOPER_H

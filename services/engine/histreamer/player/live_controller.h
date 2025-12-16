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

#ifndef LIVE_CONTROLLER_H
#define LIVE_CONTROLLER_H

#include "i_player_engine.h"
#include "osal/task/mutex.h"
#include "osal/task/task.h"
#include "osal/utils/steady_clock.h"

namespace OHOS {
namespace Media {
class LiveController : public IPlayerEngineObs {
public:
    explicit LiveController();

    ~LiveController() override;

    void Stop();

    void StartWithPlayerEngineObs(const std::weak_ptr<IPlayerEngineObs>& obs);

    void CreateTask(std::string playerId);

    void StartCheckLiveDelayTime(int64_t updateIntervalMs = 1000);

    void StopCheckLiveDelayTime();

    void OnError(PlayerErrorType errorType, int32_t errorCode, const std::string &description) override;

    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody) override;

    void OnSystemOperation(PlayerOnSystemOperationType type, PlayerOperationReason reason) override;

private:
    struct Event {
        Event(int32_t inWhat, int64_t inWhenMs, Any inAny): what(inWhat), whenMs(inWhenMs),
            detail(std::move(inAny)) {}
        int32_t what {0};
        int64_t whenMs {INT64_MAX};
        Any detail;
    };

    void Enqueue(const std::shared_ptr<Event>& event);

    void LoopOnce(const std::shared_ptr<Event>& item);

    void DoCheckLiveDelayTime();

    bool taskStarted_ {false};

    std::atomic<bool> isCheckLiveDelayTimeSet_ = false;

    std::unique_ptr<OHOS::Media::Task> task_;

    std::weak_ptr<IPlayerEngineObs> obs_ {};

    int64_t checkLiveDelayTimeIntervalMs_ {1000};
};
} // namespace Media
} // namespace OHOS
#endif // LIVE_CONTROLLER_H
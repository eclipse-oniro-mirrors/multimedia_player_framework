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

    void EnableReportMediaProgress(bool enable);
    
    void StartReportMediaProgress(int64_t updateIntervalMs = 1000);

    void StopReportMediaProgress();

    void ManualReportMediaProgressOnce();

    void OnError(PlayerErrorType errorType, int32_t errorCode, const std::string &description) override;

    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody) override;

    void OnSystemOperation(PlayerOnSystemOperationType type, PlayerOperationReason reason) override;

    void OnDfxInfo(const DfxEvent &event) override;

    void SetMaxAmplitudeCbStatus(bool status);
    void DoReportCompletedTime();
    void StartCollectMaxAmplitude(int64_t updateIntervalMs);
    void StopCollectMaxAmplitude();
    void ReportRemainedMaxAmplitude();
    void OnInfoDelay(PlayerOnInfoType type, int32_t extra, const Format &infoBody, int64_t delayMs);
    bool IsAudioPass(const char* mimeType) override;
    std::vector<std::string> GetDolbyList() override;

private:
    void DoReportMediaProgress();
    void DoReportDfxInfo(const Any& info);
    void DoReportInfo(const Any& info);
    void DoReportError(const Any& error, const std::string &description);
    void DoCollectAmplitude();
    void DoReportSystemOperation(const Any& info);

    struct Event {
        Event(int32_t inWhat, int64_t inWhenMs, Any inAny, std::string description = "")
            : what(inWhat), whenMs(inWhenMs), detail(std::move(inAny)), description(description)
        {}
        int32_t what {0};
        int64_t whenMs {INT64_MAX};
        Any detail;
        std::string description;
    };
    class EventQueue {
    public:
        void Enqueue(const std::shared_ptr<Event>& event);
        std::shared_ptr<Event> Next();
        void RemoveMediaProgressEvent();
        void Quit();
    private:
        OHOS::Media::Mutex queueMutex_ {};
        OHOS::Media::ConditionVariable queueHeadUpdatedCond_ {};
        std::list<std::shared_ptr<Event>> queue_ {};
        bool quit_ {false};
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
    bool reportUV_ {true};
    bool reportUVProgressLoopRunning_ {false};
    bool enableReportMediaProgress_ {true};
    bool isReportMediaProgressLoopRunning_ {false};
    int64_t reportProgressIntervalMs_ {100}; // default interval is 100 ms
    int64_t collectMaxAmplitudeIntervalMs_ {100}; // default interval is 100 ms
    std::vector<float> vMaxAmplitudeArray_ {};
};
}  // namespace Media
}  // namespace OHOS
#endif // HISTREAMER_HIPLAYER_CALLBACKER_LOOPER_H

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

#define HST_LOG_TAG "CallbackLooper"

#include "hiplayer_callback_looper.h"
#include <utility>
#include "common/log.h"
#include "osal/task/autolock.h"
#include "osal/utils/steady_clock.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "HiPlayerCallbackLooper" };
}

namespace OHOS {
namespace Media {
namespace {
constexpr int32_t WHAT_NONE = 0;
constexpr int32_t WHAT_MEDIA_PROGRESS = 1;
constexpr int32_t WHAT_INFO = 2;
constexpr int32_t WHAT_ERROR = 3;
constexpr int32_t WHAT_COLLECT_AMPLITUDE = 4;
constexpr int32_t WHAT_SYSTEM_OPERATION = 5;
constexpr int32_t WHAT_DFX_INFO = 6;

constexpr int32_t TUPLE_POS_0 = 0;
constexpr int32_t TUPLE_POS_1 = 1;
constexpr int32_t TUPLE_POS_2 = 2;
constexpr int32_t MAX_AMPLITUDE_SIZE = 5;
}
HiPlayerCallbackLooper::HiPlayerCallbackLooper()
{
}

HiPlayerCallbackLooper::~HiPlayerCallbackLooper()
{
    Stop();
}

bool HiPlayerCallbackLooper::IsStarted()
{
    return taskStarted_;
}

void HiPlayerCallbackLooper::Stop()
{
    if (taskStarted_) {
        task_->Stop();
        taskStarted_ = false;
    }
}

void HiPlayerCallbackLooper::SetMaxAmplitudeCbStatus(bool status)
{
    MEDIA_LOG_I("HiPlayerCallbackLooper SetMaxAmplitudeCbStatus");
    OHOS::Media::AutoLock lock(loopMutex_);
    FALSE_RETURN(reportUV_ != status);

    reportUV_ = status;
    FALSE_RETURN(reportUV_ && collectMaxAmplitude_ && !reportUVProgressLoopRunning_);
    reportUVProgressLoopRunning_ = true;
    Enqueue(std::make_shared<Event>(WHAT_COLLECT_AMPLITUDE,
        SteadyClock::GetCurrentTimeMs() + collectMaxAmplitudeIntervalMs_, Any()));
}

void HiPlayerCallbackLooper::StartWithPlayerEngineObs(const std::weak_ptr<IPlayerEngineObs>& obs)
{
    OHOS::Media::AutoLock lock(loopMutex_);
    obs_ = obs;
    if (!taskStarted_) {
        task_->Start();
        taskStarted_ = true;
        MEDIA_LOG_I("start callback looper");
    }
}
void HiPlayerCallbackLooper::SetPlayEngine(IPlayerEngine* engine, std::string playerId)
{
    OHOS::Media::AutoLock lock(loopMutex_);
    playerEngine_ = engine;
    task_ = std::make_unique<Task>("callbackThread", playerId, TaskType::GLOBAL, TaskPriority::NORMAL, false);
}

void HiPlayerCallbackLooper::EnableReportMediaProgress(bool enable)
{
    MEDIA_LOG_D("EnableReportMediaProgress, enable: " PUBLIC_LOG_D32, static_cast<int32_t>(enable));
    OHOS::Media::AutoLock lock(loopMutex_);
    FALSE_RETURN(enableReportMediaProgress_ != enable);
    enableReportMediaProgress_ = enable;
    FALSE_RETURN(reportMediaProgress_ && enableReportMediaProgress_ && !isReportMediaProgressLoopRunning_);
    isReportMediaProgressLoopRunning_ = true;
    Enqueue(std::make_shared<Event>(WHAT_MEDIA_PROGRESS,
            SteadyClock::GetCurrentTimeMs() + reportProgressIntervalMs_, Any()));
}

void HiPlayerCallbackLooper::StartReportMediaProgress(int64_t updateIntervalMs)
{
    MEDIA_LOG_I("HiPlayerCallbackLooper StartReportMediaProgress");
    OHOS::Media::AutoLock lock(loopMutex_);
    reportProgressIntervalMs_ = updateIntervalMs;
    if (reportMediaProgress_) { // already set
        return;
    }
    reportMediaProgress_ = true;
    FALSE_RETURN(enableReportMediaProgress_);
    isReportMediaProgressLoopRunning_ = true;
    Enqueue(std::make_shared<Event>(WHAT_MEDIA_PROGRESS,
            SteadyClock::GetCurrentTimeMs() + reportProgressIntervalMs_, Any()));
}

void HiPlayerCallbackLooper::StartCollectMaxAmplitude(int64_t updateIntervalMs)
{
    MEDIA_LOG_I("HiPlayerCallbackLooper StartCollectMaxAmplitude");
    OHOS::Media::AutoLock lock(loopMutex_);
    collectMaxAmplitudeIntervalMs_ = updateIntervalMs;
    if (collectMaxAmplitude_) { // already set
        return;
    }
    collectMaxAmplitude_ = true;
    FALSE_RETURN(reportUV_);
    reportUVProgressLoopRunning_ = true;
    Enqueue(std::make_shared<Event>(WHAT_COLLECT_AMPLITUDE,
        SteadyClock::GetCurrentTimeMs() + collectMaxAmplitudeIntervalMs_, Any()));
}

void HiPlayerCallbackLooper::ManualReportMediaProgressOnce()
{
    Enqueue(std::make_shared<Event>(WHAT_MEDIA_PROGRESS, SteadyClock::GetCurrentTimeMs(), Any()));
}

void HiPlayerCallbackLooper::StopReportMediaProgress()
{
    MEDIA_LOG_D("HiPlayerCallbackLooper StopReportMediaProgress");
    OHOS::Media::AutoLock lock(loopMutex_);
    reportMediaProgress_ = false;
}

void HiPlayerCallbackLooper::StopCollectMaxAmplitude()
{
    MEDIA_LOG_D("HiPlayerCallbackLooper StopCollectMaxAmplitude");
    OHOS::Media::AutoLock lock(loopMutex_);
    collectMaxAmplitude_ = false;
}

void HiPlayerCallbackLooper::DoReportCompletedTime()
{
    OHOS::Media::AutoLock lock(loopMutex_);
    auto obs = obs_.lock();
    if (obs) {
        Format format;
        int32_t playRangeEndTime = static_cast<int32_t>(playerEngine_->GetPlayRangeEndTime());
        if (playRangeEndTime != -1) {
            MEDIA_LOG_D("EVENT_AUDIO_PROGRESS endTime position updated: " PUBLIC_LOG_D32, playRangeEndTime);
            obs->OnInfo(INFO_TYPE_POSITION_UPDATE, playRangeEndTime, format);
        } else {
            int32_t currentPositionMs;
            if (playerEngine_->GetDuration(currentPositionMs) == 0) {
                MEDIA_LOG_D("EVENT_AUDIO_PROGRESS completed position updated: " PUBLIC_LOG_D32, currentPositionMs);
                obs->OnInfo(INFO_TYPE_POSITION_UPDATE, currentPositionMs, format);
            } else {
                MEDIA_LOG_W("get player engine current time error");
            }
        }
    }
}

void HiPlayerCallbackLooper::DoReportMediaProgress()
{
    OHOS::Media::AutoLock lock(loopMutex_);
    if (!reportMediaProgress_ || !enableReportMediaProgress_) {
        isReportMediaProgressLoopRunning_ = false;
        return;
    }
    auto obs = obs_.lock();
    if (obs && !isDropMediaProgress_) {
        Format format;
        int32_t currentPositionMs;
        if (playerEngine_->GetCurrentTime(currentPositionMs) == 0) {
            MEDIA_LOG_D("EVENT_AUDIO_PROGRESS position updated: " PUBLIC_LOG_D32, currentPositionMs);
            obs->OnInfo(INFO_TYPE_POSITION_UPDATE, currentPositionMs, format);
        } else {
            MEDIA_LOG_D("get player engine current time error");
        }
    }
    isDropMediaProgress_ = false;
    Enqueue(std::make_shared<Event>(WHAT_MEDIA_PROGRESS,
        SteadyClock::GetCurrentTimeMs() + reportProgressIntervalMs_, Any()));
}

void HiPlayerCallbackLooper::DoCollectAmplitude()
{
    OHOS::Media::AutoLock lock(loopMutex_);
    if (!collectMaxAmplitude_ || !reportUV_) {
        reportUVProgressLoopRunning_ = false;
        return;
    }
    auto obs = obs_.lock();
    if (obs) {
        float maxAmplitude = 0.0f;
        maxAmplitude = playerEngine_->GetMaxAmplitude();
        vMaxAmplitudeArray_.push_back(maxAmplitude);
        if (vMaxAmplitudeArray_.size() == MAX_AMPLITUDE_SIZE) {
            int mSize = static_cast<int>(vMaxAmplitudeArray_.size());
            const int size = mSize;
            float* maxAmplitudeArray = vMaxAmplitudeArray_.data();
            Format amplitudeFormat;
            (void)amplitudeFormat.PutBuffer(std::string(PlayerKeys::AUDIO_MAX_AMPLITUDE),
                static_cast<uint8_t *>(static_cast<void *>(maxAmplitudeArray)), size * sizeof(float));
            obs->OnInfo(INFO_TYPE_MAX_AMPLITUDE_COLLECT, 0, amplitudeFormat);
            vMaxAmplitudeArray_.clear();
        }
    }

    Enqueue(std::make_shared<Event>(WHAT_COLLECT_AMPLITUDE,
        SteadyClock::GetCurrentTimeMs() + collectMaxAmplitudeIntervalMs_, Any()));
}

void HiPlayerCallbackLooper::ReportRemainedMaxAmplitude()
{
    OHOS::Media::AutoLock lock(loopMutex_);
    auto obs = obs_.lock();
    if (obs != nullptr) {
        if (vMaxAmplitudeArray_.size() != 0) {
            const int size = static_cast<int>(vMaxAmplitudeArray_.size());
            float* maxAmplitudeArray = vMaxAmplitudeArray_.data();
            Format amplitudeFormat;
            (void)amplitudeFormat.PutBuffer(std::string(PlayerKeys::AUDIO_MAX_AMPLITUDE),
                static_cast<uint8_t *>(static_cast<void *>(maxAmplitudeArray)), size * sizeof(float));
            obs->OnInfo(INFO_TYPE_MAX_AMPLITUDE_COLLECT, 0, amplitudeFormat);
            vMaxAmplitudeArray_.clear();
        }
    }
}

void HiPlayerCallbackLooper::DoReportSystemOperation(const Any& info)
{
    std::shared_ptr<IPlayerEngineObs> obs;
    {
        OHOS::Media::AutoLock lock(loopMutex_);
        obs = obs_.lock();
    }
    if (obs) {
        auto ptr = AnyCast<std::pair<PlayerOnSystemOperationType, PlayerOperationReason>>(&info);
        if (ptr == nullptr) {
            MEDIA_LOG_E_SHORT("DoReportSystemOperation, ptr is nullptr");
            return;
        }
        MEDIA_LOG_I("Do Report SystemOperation, type: " PUBLIC_LOG_D32 " resaon: " PUBLIC_LOG_D32,
            static_cast<int32_t>(ptr->first), static_cast<int32_t>(ptr->second));
        obs->OnSystemOperation(ptr->first, ptr->second);
    }
}

void HiPlayerCallbackLooper::OnError(PlayerErrorType errorType, int32_t errorCode, const std::string &description)
{
    Enqueue(std::make_shared<HiPlayerCallbackLooper::Event>(WHAT_ERROR, SteadyClock::GetCurrentTimeMs(),
        std::make_pair(errorType, errorCode), description));
}

void HiPlayerCallbackLooper::DoReportError(const Any &error, const std::string &description)
{
    OHOS::Media::AutoLock lock(loopMutex_);
    auto obs = obs_.lock();
    if (obs != nullptr) {
        auto ptr = AnyCast<std::pair<PlayerErrorType, int32_t>>(&error);
        if (ptr == nullptr) {
            MEDIA_LOG_E_SHORT("DoReportError error, ptr is nullptr");
            return;
        }
        MEDIA_LOG_E("Report error, error type: " PUBLIC_LOG_D32 " error value: " PUBLIC_LOG_D32,
            static_cast<int32_t>(ptr->first), static_cast<int32_t>(ptr->second));
        obs->OnError(ptr->first, ptr->second, description);
    }
}

void HiPlayerCallbackLooper::OnSystemOperation(PlayerOnSystemOperationType type, PlayerOperationReason reason)
{
    Enqueue(std::make_shared<HiPlayerCallbackLooper::Event>(WHAT_SYSTEM_OPERATION, SteadyClock::GetCurrentTimeMs(),
        std::make_pair(type, reason)));
}

void HiPlayerCallbackLooper::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    Enqueue(std::make_shared<HiPlayerCallbackLooper::Event>(WHAT_INFO, SteadyClock::GetCurrentTimeMs(),
        std::make_tuple(type, extra, infoBody)));
}

void HiPlayerCallbackLooper::OnDfxInfo(const DfxEvent &event)
{
    Enqueue(std::make_shared<HiPlayerCallbackLooper::Event>(WHAT_DFX_INFO, SteadyClock::GetCurrentTimeMs(), event));
}

void HiPlayerCallbackLooper::DoReportDfxInfo(const Any& info)
{
    auto obs = obs_.lock();
    if (obs != nullptr) {
        auto ptr = AnyCast<DfxEvent>(&info);
        if (ptr == nullptr) {
            MEDIA_LOG_E_SHORT("DoReportDfxInfo error, ptr is nullptr");
            return;
        }
        MEDIA_LOG_DD("Report Dfx, callerName: " PUBLIC_LOG_S " type: " PUBLIC_LOG_D32,
            ptr->callerName.c_str(), static_cast<int32_t>(ptr->type));
        obs->OnDfxInfo(*ptr);
    }
}

void HiPlayerCallbackLooper::DoReportInfo(const Any& info)
{
    auto obs = obs_.lock();
    if (obs != nullptr) {
        auto ptr = AnyCast<std::tuple<PlayerOnInfoType, int32_t, Format>>(&info);
        if (ptr == nullptr) {
            MEDIA_LOG_E_SHORT("DoReportInfo error, ptr is nullptr");
            return;
        }
        MEDIA_LOG_D("Report info, info type: " PUBLIC_LOG_D32 " info value: " PUBLIC_LOG_D32,
            static_cast<int32_t>(std::get<TUPLE_POS_0>(*ptr)), static_cast<int32_t>(std::get<TUPLE_POS_1>(*ptr)));
        obs->OnInfo(std::get<TUPLE_POS_0>(*ptr), std::get<TUPLE_POS_1>(*ptr), std::get<TUPLE_POS_2>(*ptr));
    }
}

void HiPlayerCallbackLooper::LoopOnce(const std::shared_ptr<HiPlayerCallbackLooper::Event>& item)
{
    switch (item->what) {
        case WHAT_MEDIA_PROGRESS:
            DoReportMediaProgress();
            break;
        case WHAT_INFO:
            DoReportInfo(item->detail);
            break;
        case WHAT_ERROR:
            DoReportError(item->detail, item->description);
            break;
        case WHAT_COLLECT_AMPLITUDE:
            DoCollectAmplitude();
            break;
        case WHAT_SYSTEM_OPERATION:
            DoReportSystemOperation(item->detail);
            break;
        case WHAT_DFX_INFO:
            DoReportDfxInfo(item->detail);
            break;
        default:
            break;
    }
}

void HiPlayerCallbackLooper::Enqueue(const std::shared_ptr<HiPlayerCallbackLooper::Event>& event)
{
    if (!event) {
        return;
    }
    if (event->what == WHAT_NONE) {
        MEDIA_LOG_I("invalid event");
    }
    int64_t delayUs = (event->whenMs - SteadyClock::GetCurrentTimeMs()) * 1000;
    task_->SubmitJob([this, event]() {
        LoopOnce(event);
    }, delayUs);
}

void HiPlayerCallbackLooper::OnInfoDelay(PlayerOnInfoType type, int32_t extra, const Format &infoBody, int64_t delayMs)
{
    Enqueue(std::make_shared<HiPlayerCallbackLooper::Event>(WHAT_INFO, SteadyClock::GetCurrentTimeMs() + delayMs,
        std::make_tuple(type, extra, infoBody)));
}
}  // namespace Media
}  // namespace OHOS
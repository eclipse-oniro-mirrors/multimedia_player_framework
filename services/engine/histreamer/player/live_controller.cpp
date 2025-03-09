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

#define HST_LOG_TAG "LiveControl"

#include "live_control.h"
#include "common/log.h"
#include "osal/task/autolock.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "LiveControl" };
}

namespace OHOS {
namespace Media {
namespace {
constexpr int32_t WHAT_NONE = 0;
constexpr int32_t WHAT_LIVE_DELAY_TIME = 1;
}
LiveControl::LiveControl()
{
}

LiveControl::~LiveControl()
{
    Stop();
}

void LiveControl::Stop()
{
    if (taskStarted_) {
        task_->Stop();
        taskStarted_ = false;
    }
}

void LiveControl::StartWithPlayerEngineObs(const std::weak_ptr<IPlayerEngineObs>& obs)
{
    OHOS::Media::AutoLock lock(loopMutex_);
    obs_ = obs;
    if (!taskStarted_) {
        task_->Start();
        taskStarted_ = true;
        MEDIA_LOG_I("start check live delay looper");
    }
}

void LiveControl::SetPlayEngine(IPlayerEngine* engine, std::string playerId)
{
    OHOS::Media::AutoLock lock(loopMutex_);
    playerEngine_ = engine;
    task_ = std::make_unique<Task>("checkliveDelayThread", playerId, TaskType::GLOBAL, TaskPriority::NORMAL, false);
}

void LiveControl::StartCheckLiveDelayTime(int64_t updateIntervalMs)
{
    MEDIA_LOG_I("LiveControl StartCheckLiveDalyTime");
    checkLiveDelayTimeIntervalMs_ = updateIntervalMs;
    if (isCheckLiveDelayTimeSet_) { // already set
        return;
    }
    isCheckLiveDelayTimeSet_ = true;
    Enqueue(std::make_shared<Event>(WHAT_LIVE_DELAY_TIME,
            SteadyClock::GetCurrentTimeMs() + checkLiveDelayTimeIntervalMs_, Any()));
}

void LiveControl::StopCheckLiveDalyTime()
{
    MEDIA_LOG_I("LiveControl::StopCheckLiveDalyTime");
    OHOS::Media::AutoLock lock(loopMutex_);
    isCheckLiveDelayTimeSet_ = false;
}

void LiveControl::Enqueue(const std::shared_ptr<LiveControl::Event>& event)
{
    if (event->what == WHAT_NONE) {
        MEDIA_LOG_I("invalid event");
    }
    int64_t delayUs = (event->whenMs - SteadyClock::GetCurrentTimeMs()) * 1000;
    task_->SubmitJob([this, event]() {
        LoopOnce(event);
        }, delayUs);
}

void LiveControl::LoopOnce(const std::shared_ptr<Event>& item)
{
    switch (item->what) {
        case WHAT_LIVE_DELAY_TIME:
            DoCheckLiveDalyTime();
            break;
        default:
            break;
    }
}

void LiveControl::DoCheckLiveDalyTime()
{
    OHOS::Media::AutoLock lock(loopMutex_);
    if (!isCheckLiveDelayTimeSet_) {
        return;
    }
    auto obs = obs_.lock();
    if (obs) {
        obs->OnSystemOperation(OPERATION_TYPE_CHECK_LIVE_DELAY, OPERATION_REASON_CHECK_LIVE_DELAY_TIME);
    }
    if (isCheckLiveDelayTimeSet_) {
        Enqueue(std::make_shared<Event>(WHAT_LIVE_DELAY_TIME,
            SteadyClock::GetCurrentTimeMs() + checkLiveDelayTimeIntervalMs_, Any()));
    }
}

void LiveControl::OnError(PlayerErrorType errorType, int32_t errorCode)
{
    (void)errorType;
    (void)errorCode;
}

void LiveControl::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    (void)type;
    (void)extra;
    (void)infoBody;
}

void LiveControl::OnSystemOperation(PlayerOnSystemOperationType type, PlayerOperationReason reason)
{
    (void)type;
    (void)reason;
}
}  // namespace Media
}  // namespace OHOS
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

#define HST_LOG_TAG "LiveController"

#include "live_controller.h"
#include "common/log.h"
#include "osal/task/autolock.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "LiveController" };
}

namespace OHOS {
namespace Media {
namespace {
constexpr int32_t WHAT_NONE = 0;
constexpr int32_t WHAT_LIVE_DELAY_TIME = 1;
}
LiveController::LiveController()
{
}

LiveController::~LiveController()
{
    Stop();
}

void LiveController::Stop()
{
    if (taskStarted_) {
        FALSE_RETURN(task_ != nullptr);
        task_->Stop();
        taskStarted_ = false;
    }
}

void LiveController::StartWithPlayerEngineObs(const std::weak_ptr<IPlayerEngineObs>& obs)
{
    obs_ = obs;
    if (!taskStarted_) {
        FALSE_RETURN(task_ != nullptr);
        task_->Start();
        taskStarted_ = true;
        MEDIA_LOG_I("start check live delay looper");
    }
}

void LiveController::CreateTask(std::string playerId)
{
    task_ = std::make_unique<Task>("checkliveDelayThread", playerId, TaskType::GLOBAL, TaskPriority::NORMAL, false);
}

void LiveController::StartCheckLiveDelayTime(int64_t updateIntervalMs)
{
    MEDIA_LOG_I("LiveController StartCheckLiveDelayTime, check interval is " PUBLIC_LOG_D64 " ms", updateIntervalMs);
    checkLiveDelayTimeIntervalMs_ = updateIntervalMs;
    if (isCheckLiveDelayTimeSet_.load()) { // already set
        return;
    }
    isCheckLiveDelayTimeSet_.store(true);
    Enqueue(std::make_shared<Event>(WHAT_LIVE_DELAY_TIME,
            SteadyClock::GetCurrentTimeMs() + checkLiveDelayTimeIntervalMs_, Any()));
}

void LiveController::StopCheckLiveDelayTime()
{
    MEDIA_LOG_I("LiveController::StopCheckLiveDelayTime");
    isCheckLiveDelayTimeSet_.store(false);
}

void LiveController::Enqueue(const std::shared_ptr<LiveController::Event>& event)
{
    FALSE_RETURN(event != nullptr && task_ != nullptr);
    if (event->what == WHAT_NONE) {
        MEDIA_LOG_I("invalid event");
    }
    int64_t delayUs = (event->whenMs - SteadyClock::GetCurrentTimeMs()) * 1000;
    task_->SubmitJob([this, event]() {
        LoopOnce(event);
        }, delayUs);
}

void LiveController::LoopOnce(const std::shared_ptr<Event>& item)
{
    FALSE_RETURN(item != nullptr);
    switch (item->what) {
        case WHAT_LIVE_DELAY_TIME:
            DoCheckLiveDelayTime();
            break;
        default:
            break;
    }
}

void LiveController::DoCheckLiveDelayTime()
{
    if (!isCheckLiveDelayTimeSet_.load()) {
        return;
    }
    auto obs = obs_.lock();
    if (obs) {
        obs->OnSystemOperation(OPERATION_TYPE_CHECK_LIVE_DELAY, OPERATION_REASON_CHECK_LIVE_DELAY_TIME);
    }
    if (isCheckLiveDelayTimeSet_.load()) {
        Enqueue(std::make_shared<Event>(WHAT_LIVE_DELAY_TIME,
            SteadyClock::GetCurrentTimeMs() + checkLiveDelayTimeIntervalMs_, Any()));
    }
}

void LiveController::OnError(PlayerErrorType errorType, int32_t errorCode, const std::string &description)
{
    (void)errorType;
    (void)errorCode;
    (void)description;
}

void LiveController::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    (void)type;
    (void)extra;
    (void)infoBody;
}

void LiveController::OnSystemOperation(PlayerOnSystemOperationType type, PlayerOperationReason reason)
{
    (void)type;
    (void)reason;
}
}  // namespace Media
}  // namespace OHOS
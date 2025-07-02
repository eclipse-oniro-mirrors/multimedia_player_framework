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

#define HST_LOG_TAG "CallbackLooper"

#include "lpp_audio_callback_looper.h"
#include <utility>
#include "common/log.h"
#include "osal/task/autolock.h"
#include "osal/utils/steady_clock.h"
#include "plugin/plugin_time.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppAudioCallbackLooper"};
constexpr int64_t POSITION_UPDATE_INTERVAL_US = 100 * 1000; // report position update per 100ms
constexpr int64_t US_TO_MS = 1000;  // 1000 us per ms
}

namespace OHOS {
namespace Media {

LppAudioCallbackLooper::LppAudioCallbackLooper(std::string lppAudioStreamerId)
{
    lppAudioStreamerId_ = lppAudioStreamerId;
    task_ = std::make_unique<Task>("callbackThread", lppAudioStreamerId_, TaskType::GLOBAL, TaskPriority::NORMAL,
        false);
}

LppAudioCallbackLooper::~LppAudioCallbackLooper()
{
    MEDIA_LOG_I("LppAudioCallbackLooper::~LppAudioCallbackLooper in");
    Stop();
    MEDIA_LOG_I("LppAudioCallbackLooper::~LppAudioCallbackLooper out");
}

void LppAudioCallbackLooper::OnDataNeeded(const int32_t maxBufferSize)
{
    MEDIA_LOG_D("lppAudio OnDataNeeded maxBufferSize" PUBLIC_LOG_D32, maxBufferSize);
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    task_->SubmitJob([this, maxBufferSize]() {
        auto obs = obs_.lock();
        FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
        MEDIA_LOG_I("submit OnDataNeeded");
        obs->OnDataNeeded(maxBufferSize);
    });
}
void LppAudioCallbackLooper::OnPositionUpdated(const int64_t currentPositionMs)
{
    MEDIA_LOG_W("LppAudioCallbackLooper not support OnPositionUpdated, please call StartPositionUpdate");
    (void)currentPositionMs;
}
void LppAudioCallbackLooper::OnError(const MediaServiceErrCode errCode, const std::string &errMsg)
{
    MEDIA_LOG_I("LppAudioCallbackLooper::OnError" PUBLIC_LOG_S, errMsg.c_str());
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    task_->SubmitJob([this, errCode, localMsg = errMsg]() {
        auto obs = obs_.lock();
        FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
        MEDIA_LOG_I("submit OnError");
        obs->OnError(errCode, localMsg);
    });
}
void LppAudioCallbackLooper::OnEos()
{
    MEDIA_LOG_I("LppAudioCallbackLooper::OnEos");
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    task_->SubmitJob([this]() {
        auto obs = obs_.lock();
        FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
        MEDIA_LOG_I("submit OnEos");
        obs->OnEos();
    });
}
void LppAudioCallbackLooper::OnInterrupted(const int64_t forceType, const int64_t hint)
{
    MEDIA_LOG_I("LppAudioCallbackLooper::OnInterrupted forceType" PUBLIC_LOG_D64, forceType);
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    task_->SubmitJob([this, forceType, hint]() {
        auto obs = obs_.lock();
        FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
        MEDIA_LOG_I("submit OnInterrupted");
        obs->OnInterrupted(forceType, hint);
    });
}
void LppAudioCallbackLooper::OnDeviceChanged(const int64_t reason)
{
    MEDIA_LOG_I("LppAudioCallbackLooper::OnDeviceChanged reason" PUBLIC_LOG_D64, reason);
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    task_->SubmitJob([this, reason]() {
        auto obs = obs_.lock();
        FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
        MEDIA_LOG_I("submit OnDeviceChanged");
        obs->OnDeviceChanged(reason);
    });
}

void LppAudioCallbackLooper::StartPositionUpdate()
{
    MEDIA_LOG_I("LppAudioCallbackLooper::StartPositionUpdate");
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    task_->SubmitJob([this, positionUpdateIdx = positionUpdateIdx_.load()]() {
        DoPositionUpdate(positionUpdateIdx);
    });
}

void LppAudioCallbackLooper::DoPositionUpdate(int64_t positionUpdateIdx)
{
    FALSE_RETURN_MSG(positionUpdateIdx == positionUpdateIdx_.load(), "DoPositionUpdate out of date");
    auto obs = obs_.lock();
    FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
    int64_t currentPosition = Plugins::HST_TIME_NONE;
    auto ret = GetCurrentPosition(currentPosition);
    if (ret == MSERR_OK && currentPosition != Plugins::HST_TIME_NONE) {
        MEDIA_LOG_D("position updated: " PUBLIC_LOG_D64, currentPosition);
        obs->OnPositionUpdated(currentPosition / US_TO_MS);
    }
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    task_->SubmitJob([this, positionUpdateIdx]() {
            DoPositionUpdate(positionUpdateIdx);
        }, POSITION_UPDATE_INTERVAL_US, false);
}

void LppAudioCallbackLooper::StopPositionUpdate()
{
    MEDIA_LOG_I("LppAudioCallbackLooper::StopPositionUpdate");
    positionUpdateIdx_.fetch_add(1);
}

int32_t LppAudioCallbackLooper::GetCurrentPosition(int64_t &currentPosition)
{
    auto engine = engine_.lock();
    FALSE_RETURN_V_MSG(engine != nullptr, MSERR_INVALID_STATE, "engine is nullptr");
    return engine->GetCurrentPosition(currentPosition);
}

void LppAudioCallbackLooper::Stop()
{
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    task_->Stop();
}

void LppAudioCallbackLooper::Reset()
{
    Stop();
}

void LppAudioCallbackLooper::StartWithLppAudioStreamerEngineObs(const std::weak_ptr<ILppAudioStreamerEngineObs> &obs)
{
    MEDIA_LOG_I("LppAudioCallbackLooper::StartWithLppAudioStreamerEngineObs");
    obs_ = obs;
    MEDIA_LOG_I("start callback looper");
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    task_->Start();
}

void LppAudioCallbackLooper::SetEngine(std::weak_ptr<ILppAudioStreamerEngine> engine)
{
    engine_ = engine;
}
}  // namespace Media
}  // namespace OHOS
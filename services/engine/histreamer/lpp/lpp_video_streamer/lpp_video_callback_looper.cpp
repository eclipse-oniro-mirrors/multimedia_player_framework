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
 
#include "lpp_video_callback_looper.h"
#include <utility>
#include "common/log.h"
#include "osal/task/autolock.h"
#include "osal/utils/steady_clock.h"
 
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "LppVideoCallbackLooper" };
}
 
namespace OHOS {
namespace Media {

LppVideoCallbackLooper::LppVideoCallbackLooper(std::string lppVideoStreamerId)
{
    lppVideoStreamerId_ = lppVideoStreamerId;
    task_ = std::make_unique<Task>("callbackThread", lppVideoStreamerId_, TaskType::VIDEO, TaskPriority::NORMAL, false);
}
 
LppVideoCallbackLooper::~LppVideoCallbackLooper()
{
    Stop();
}
 
void LppVideoCallbackLooper::OnDataNeeded(const int32_t maxBufferSize, const int32_t maxFrameNum)
{
    MEDIA_LOG_I("OnDataNeeded call maxBufferSize" PUBLIC_LOG_D32, maxBufferSize);
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    auto obs = obs_.lock();
    if (obs) {
        task_->SubmitJob([maxBufferSize, maxFrameNum, obs]() {
            MEDIA_LOG_I("submit OnDataNeeded");
            obs->OnDataNeeded(maxBufferSize, maxFrameNum);
        });
    }
}

bool LppVideoCallbackLooper::OnAnchorUpdateNeeded(int64_t &anchorPts, int64_t &anchorClk)
{
    MEDIA_LOG_I("LppVideoCallbackLooper::OnAnchorUpdateNeeded %{public}s", "Anchor update needed");
    return true;
}

void LppVideoCallbackLooper::OnError(const LppErrCode errCode, const std::string &errMsg)
{
    MEDIA_LOG_I("LppVideoCallbackLooper::OnError errMsg: %{public}s", errMsg.c_str());
}

void LppVideoCallbackLooper::OnEos()
{
    MEDIA_LOG_I("LppVideoCallbackLooper::OnEos %{public}s", "End of stream");
    auto obs = obs_.lock();
    FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
    obs->OnEos();
}

void LppVideoCallbackLooper::OnRenderStarted()
{
    MEDIA_LOG_I("LppVideoCallbackLooper::OnRenderStarted %{public}s", "Render started");
    auto obs = obs_.lock();
    FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
    obs->OnRenderStarted();
}

void LppVideoCallbackLooper::OnFirstFrameReady()
{
    MEDIA_LOG_I("LppVideoCallbackLooper::OnFirstFrameReady %{public}s", "first frame ready");
    auto obs = obs_.lock();
    FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
    obs->OnFirstFrameReady();
}

void LppVideoCallbackLooper::OnTargetArrived(const int64_t targetPts, const bool isTimeout)
{
    MEDIA_LOG_I("LppVideoCallbackLooper::OnTargetArrived %{public}s", "Target arrived");
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    auto obs = obs_.lock();
    if (obs) {
        task_->SubmitJob([targetPts, isTimeout, obs]() {
            MEDIA_LOG_I("submit OnTargetArrived");
            obs->OnTargetArrived(targetPts, isTimeout);
        });
    }
}

void LppVideoCallbackLooper::OnStreamChanged(Format &format)
{
    MEDIA_LOG_I("LppVideoCallbackLooper::OnStreamChanged");
    auto obs = obs_.lock();
    FALSE_RETURN_MSG(obs != nullptr, "obs is nullptr");
    obs->OnStreamChanged(format);
}

void LppVideoCallbackLooper::Stop()
{
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    if (taskStarted_) {
        task_->Stop();
        taskStarted_ = false;
    }
}

void LppVideoCallbackLooper::Reset()
{
    Stop();
}
 
void LppVideoCallbackLooper::StartWithLppVideoStreamerEngineObs(const std::weak_ptr<ILppVideoStreamerEngineObs>& obs)
{
    MEDIA_LOG_I("StartWithLppVideoStreamerEngineObs");
    FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
    obs_ = obs;
    if (!taskStarted_) {
        MEDIA_LOG_I("start callback looper");
        task_->Start();
        taskStarted_ = true;
    }
}
 
}  // namespace Media
}  // namespace OHOS
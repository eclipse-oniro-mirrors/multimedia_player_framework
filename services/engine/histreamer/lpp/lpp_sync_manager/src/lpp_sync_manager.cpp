/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "lpp_sync_manager.h"
#include "common/log.h"
#include "media_errors.h"
#include "osal/utils/steady_clock.h"
#include "plugin/plugin_time.h"

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppSyncManager"};
}

LppSyncManager::LppSyncManager(std::string videoStreamerId, bool isLpp)
{
    MEDIA_LOG_I("LppSyncManager construct.");
    videoStreamerId_ = videoStreamerId;
    videoIsLpp_ = isLpp;
}

int32_t LppSyncManager::Init()
{
    MEDIA_LOG_I("LppSyncManager::Init");
    FALSE_RETURN_V_MSG_W(videoIsLpp_, MSERR_OK, "videoIsLpp_ is false, not create adapter");
    int32_t ret = LowPowerPlayerFactory::CreateLppSyncManagerAdapter(adapterId_, adapter_);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "create lpp sync manager failed");
    ret = adapter_->Init();
    FALSE_RETURN_V_MSG(ret == MSERR_OK, ret, "SyncMananger RegisterCallback failed");
    return MSERR_OK;
}

LppSyncManager::~LppSyncManager()
{
    FALSE_RETURN_MSG_W(videoIsLpp_ && adapter_ != nullptr, "videoIsLpp_ is false, not destroy adapter");
    int32_t ret = LowPowerPlayerFactory::DestroyLppSyncManagerAdapter(adapterId_, std::move(adapter_));
    adapterId_ = 0;
    adapter_ = nullptr;
    FALSE_RETURN_MSG(ret == MSERR_OK, "LppSyncManager destroy failed");
}

int32_t LppSyncManager::GetTimeAnchor(int64_t &anchorPts, int64_t &anchorClock)
{
    {
        std::lock_guard<std::mutex> lock(anchorMutex_);
        FALSE_RETURN_V_MSG_E(localAnchorClk_ != 0, MSERR_INVALID_STATE, "anchor has not been updated, can not get");
        anchorPts = localAnchorPts_;
        anchorClock = localAnchorClk_;
    }
    return MSERR_OK;
}

int32_t LppSyncManager::SetVideoChannelId(const uint32_t channelId)
{
    MEDIA_LOG_I("LppSyncManager::SetVideoChannelId Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    return adapter_->SetVideoChannelId(channelId);
}

int32_t LppSyncManager::SetAudioChannelId(const uint32_t channelId)
{
    MEDIA_LOG_I("LppSyncManager::SetAudioChannelId Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->SetAudioChannelId(channelId);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ SetAudioChannelId failed");
    return MSERR_OK;
}

int32_t LppSyncManager::Prepare()
{
    MEDIA_LOG_I("LppSyncManager::Prepare");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    return MSERR_OK;
}

int32_t LppSyncManager::StartRender()
{
    MEDIA_LOG_I("LppSyncManager::StartRender Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->StartRender();
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ StartRender failed");
    return MSERR_OK;
}

int32_t LppSyncManager::RenderNextFrame()
{
    MEDIA_LOG_I("LppSyncManager::RenderNextFrame Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->RenderNextFrame();
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ RenderNextFrame failed");
    return MSERR_OK;
}

int32_t LppSyncManager::Pause()
{
    MEDIA_LOG_I("LppSyncManager::Pause Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->Pause();
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ Pause failed");
    return MSERR_OK;
}

int32_t LppSyncManager::Resume()
{
    MEDIA_LOG_I("LppSyncManager::Resume Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->Resume();
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ Resume failed");
    return MSERR_OK;
}

int32_t LppSyncManager::Flush()
{
    MEDIA_LOG_I("LppSyncManager::Flush Enter");
    ResetTimeAnchor();
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->Flush();
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ Flush failed");
    return MSERR_OK;
}

int32_t LppSyncManager::Stop()
{
    MEDIA_LOG_I("LppSyncManager::Stop Enter");
    ResetTimeAnchor();
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->Stop();
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ Stop failed");
    return MSERR_OK;
}

int32_t LppSyncManager::Reset()
{
    MEDIA_LOG_I("LppSyncManager::Reset Enter");
    ResetTimeAnchor();
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->UnbindOutputBuffers();
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ UnbindOutputBuffers failed");
    ret = adapter_->Reset();
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ Reset failed");
    MEDIA_LOG_I("DestroyLppSyncManagerAdapter in");
    ret = LowPowerPlayerFactory::DestroyLppSyncManagerAdapter(adapterId_, std::move(adapter_));
    MEDIA_LOG_I("DestroyLppSyncManagerAdapter out");
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "LppSyncManager destroy failed");
    return MSERR_OK;
}

int32_t LppSyncManager::SetTargetStartFrame(const uint64_t targetPts, uint32_t timeoutMs)
{
    MEDIA_LOG_I("LppSyncManager::SetTargetStartFrame Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->SetTargetStartFrame(targetPts, timeoutMs);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ SetTargetStartFrame failed");
    return MSERR_OK;
}

int32_t LppSyncManager::SetPlaybackSpeed(float speed)
{
    MEDIA_LOG_I("LppSyncManager::SetPlaybackSpeed speed " PUBLIC_LOG_F, speed);
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->SetPlaybackSpeed(speed);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ SetPlaybackSpeed failed");
    return MSERR_OK;
}

int32_t LppSyncManager::SetParameter(const std::map<std::string, std::string> &parameters)
{
    MEDIA_LOG_I("LppSyncManager::SetParameter Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->SetParameter(parameters);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ SetParameter failed");
    return MSERR_OK;
}

int32_t LppSyncManager::GetParameter(std::map<std::string, std::string> &parameters)
{
    MEDIA_LOG_I("LppSyncManager::GetParameter Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->GetParameter(parameters);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ GetParameter failed");
    return MSERR_OK;
}

int32_t LppSyncManager::UpdateTimeAnchor(const int64_t anchorPts, const int64_t anchorClk)
{
    MEDIA_LOG_I("LppSyncManager::UpdateTimeAnchor Enter, pts=" PUBLIC_LOG_D64 ", clk=" PUBLIC_LOG_D64
                ", videoIsLpp_=" PUBLIC_LOG_D32,
        anchorPts,
        anchorClk,
        videoIsLpp_);
    {
        std::lock_guard<std::mutex> lock(anchorMutex_);
        localAnchorPts_ = anchorPts;
        localAnchorClk_ = anchorClk;
    }
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->UpdateTimeAnchor(anchorPts, anchorClk);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ UpdateTimeAnchor failed");
    return MSERR_OK;
}

int32_t LppSyncManager::BindOutputBuffers(const std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap)
{
    MEDIA_LOG_I("LppSyncManager::BindOutputBuffers Enter");
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->BindOutputBuffers(bufferMap);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ BindOutputBuffers failed");
    return MSERR_OK;
}

int32_t LppSyncManager::UnbindOutputBuffers()
{
    MEDIA_LOG_I("LppSyncManager::UnbindOutputBuffers Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->UnbindOutputBuffers();
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ UnbindOutputBuffers failed");
    return MSERR_OK;
}

int32_t LppSyncManager::GetShareBuffer(int32_t &fd)
{
    MEDIA_LOG_I("LppSyncManager::GetShareBuffer Enter");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->GetShareBuffer(fd);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ GetShareBuffer failed");
    return MSERR_OK;
}

int32_t LppSyncManager::SetTunnelId(uint64_t tunnelId)
{
    MEDIA_LOG_I("LppSyncManager::SetTunnelId");
    FALSE_RETURN_V_NOLOG(videoIsLpp_, MSERR_OK);
    FALSE_RETURN_V_MSG_E(adapter_ != nullptr, MSERR_NO_MEMORY, "adapter_ is nullptr");
    auto ret = adapter_->SetTunnelId(tunnelId);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "adapter_ SetTunnelId failed");
    return MSERR_OK;
}

int32_t LppSyncManager::SetAudioIsLpp(bool isLpp)
{
    audioIsLpp_ = isLpp;
    return MSERR_OK;
}

void LppSyncManager::SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver)
{
    eventReceiver_ = eventReceiver;
    FALSE_RETURN_NOLOG(videoIsLpp_);
    FALSE_RETURN_NOLOG(adapter_ != nullptr);
    adapter_->SetEventReceiver(eventReceiver);
}

void LppSyncManager::ResetTimeAnchor()
{
    std::lock_guard<std::mutex> lock(anchorMutex_);
    localAnchorPts_ = 0;
    localAnchorClk_ = 0;
}
}  // namespace Media
}  // namespace OHOS
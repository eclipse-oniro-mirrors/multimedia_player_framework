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

#define HST_LOG_TAG "LppSyncManagerAdapter"
#include <chrono>
#include "lpp_sync_manager_adapter.h"
#include "common/log.h"
#include "media_errors.h"
#include "media_lpp_errors.h"
#include "media_utils.h"
#include "surface_buffer.h"
#include "media_dfx.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppSyncManagerAdapter"};
}

namespace OHOS {
namespace Media {
using namespace OHOS::HDI::Base;

class LppSyncMgrCallback : public PlayerHDI::ILppSyncManagerCallback {
public:
    explicit LppSyncMgrCallback(std::weak_ptr<LppSyncManagerAdapter> adapter) : adapter_(adapter) {}
    virtual ~LppSyncMgrCallback() = default;
    int32_t OnError(const int32_t errorCode, const std::string &errorMsg)
    {
        MEDIA_LOG_I("LppSyncMgrCallback OnError enter");
        auto adapter = adapter_.lock();
        FALSE_RETURN_V_MSG(adapter != nullptr, HDF_FAILURE, "adapter is nullptr");
        adapter->OnError(errorCode, errorMsg);
        return HDF_SUCCESS;
    }
    int32_t OnTargetArrived(const int64_t targetPts, const bool isTimeout)
    {
        MEDIA_LOG_I("LppSyncMgrCallback OnTargetArrived enter");
        auto adapter = adapter_.lock();
        FALSE_RETURN_V_MSG(adapter != nullptr, HDF_FAILURE, "adapter is nullptr");
        adapter->OnTargetArrived(targetPts, isTimeout);
        return HDF_SUCCESS;
    }
    int32_t OnRenderStarted()
    {
        MEDIA_LOG_I("LppSyncMgrCallback OnRenderStarted enter");
        auto adapter = adapter_.lock();
        FALSE_RETURN_V_MSG(adapter != nullptr, HDF_FAILURE, "adapter is nullptr");
        adapter->OnRenderStarted();
        return HDF_SUCCESS;
    }
    int32_t OnEos()
    {
        MEDIA_LOG_I("LppSyncMgrCallback OnEos enter");
        auto adapter = adapter_.lock();
        FALSE_RETURN_V_MSG(adapter != nullptr, HDF_FAILURE, "adapter is nullptr");
        adapter->OnEos();
        return HDF_SUCCESS;
    }
    int32_t OnInfo(const int32_t infoCode, const std::string &infoMsg)
    {
        MEDIA_LOG_I("LppSyncMgrCallback OnInfo enter");
        auto adapter = adapter_.lock();
        FALSE_RETURN_V_MSG(adapter != nullptr, HDF_FAILURE, "adapter is nullptr");
        adapter->OnInfo(infoCode, infoMsg);
        return HDF_SUCCESS;
    }
    int32_t OnFirstFrameReady()
    {
        MEDIA_LOG_I("LppSyncMgrCallback OnFirstFrameReady enter");
        auto adapter = adapter_.lock();
        FALSE_RETURN_V_MSG(adapter != nullptr, HDF_FAILURE, "adapter is nullptr");
        adapter->OnFirstFrameReady();
        return HDF_SUCCESS;
    }

private:
    std::weak_ptr<LppSyncManagerAdapter> adapter_;
};

LppSyncManagerAdapter::LppSyncManagerAdapter()
{
    MEDIA_LOG_I("LppSyncManagerAdapter ctor called.");
}

LppSyncManagerAdapter::~LppSyncManagerAdapter()
{
    MEDIA_LOG_I("~LppSyncManagerAdapter dtor called.");
}

int32_t LppSyncManagerAdapter::LoadAdapter(uint32_t &instanceId)
{
    MediaTrace trace("LppSyncManagerAdapter::LoadAdapter");
    MEDIA_LOG_I("LoadAdapter enter");
    factory_ = PlayerHDI::ILowPowerPlayerFactory::Get(true);
    FALSE_RETURN_V_MSG_E(factory_ != nullptr, MSERR_VID_RENDER_FAILED, "syncMgrfactory is nullptr");
    int32_t ret = factory_->CreateSyncMgr(syncMgrAdapter_, instanceId);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS && syncMgrAdapter_ != nullptr, MSERR_VID_RENDER_FAILED,
        "Create SyncMgrAdapter failed");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::UnloadAdapter(uint32_t instanceId)
{
    MediaTrace trace("LppSyncManagerAdapter::UnloadAdapter");
    MEDIA_LOG_I("UnloadAdapter enter");
    FALSE_RETURN_V_MSG_E(factory_ != nullptr, MSERR_VID_RENDER_FAILED, "syncMgrfactory is nullptr");
    int32_t ret = factory_->DestroySyncMgr(instanceId);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "Destroy SyncMgrAdapter failed, ret");
    factory_ = nullptr;
    syncMgrAdapter_ = nullptr;
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::SetVideoChannelId(const uint32_t channelId)
{
    MediaTrace trace("LppSyncManagerAdapter::SetVideoChannelId");
    MEDIA_LOG_I("SetVideoChannelId enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->SetVideoChannelId(channelId);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger SetVideoChannelId failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::SetAudioChannelId(const uint32_t channelId)
{
    MediaTrace trace("LppSyncManagerAdapter::SetAudioChannelId");
    MEDIA_LOG_I("SetAudioChannelId enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->SetAudioChannelId(channelId);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger SetAudioChannelId failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::Init()
{
    MEDIA_LOG_I("LppSyncManagerAdapter::Init");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    sptr<LppSyncMgrCallback> lppCallback = sptr<LppSyncMgrCallback>::MakeSptr(weak_from_this());
    int32_t ret = syncMgrAdapter_->RegisterCallback(lppCallback);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger RegisterCallback failed");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::StartRender()
{
    MediaTrace trace("LppSyncManagerAdapter::StartRender");
    MEDIA_LOG_I("StartRender enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->StartRender();
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger StartRender failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::RenderNextFrame()
{
    MediaTrace trace("LppSyncManagerAdapter::RenderNextFrame");
    MEDIA_LOG_I("RenderNextFrame enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->RenderNextFrame();
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger RenderNextFrame failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::Pause()
{
    MediaTrace trace("LppSyncManagerAdapter::Pause");
    MEDIA_LOG_I("Pause enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->Pause();
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger Pause failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::Resume()
{
    MediaTrace trace("LppSyncManagerAdapter::Resume");
    MEDIA_LOG_I("Resume enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->Resume();
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger Resume failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::Flush()
{
    MediaTrace trace("LppSyncManagerAdapter::Flush");
    MEDIA_LOG_I("Flush enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    MEDIA_LOG_W("syncMgrAdapter_ flush not implememt!");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::Stop()
{
    MediaTrace trace("LppSyncManagerAdapter::Stop");
    MEDIA_LOG_I("Stop enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->Stop();
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger Stop failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::Reset()
{
    MediaTrace trace("LppSyncManagerAdapter::Reset");
    MEDIA_LOG_I("Reset enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->Reset();
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger Reset failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::SetPlaybackSpeed(float speed)
{
    MediaTrace trace("LppSyncManagerAdapter::SetPlaybackSpeed");
    MEDIA_LOG_I("SetPlaybackSpeed enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->SetPlaybackSpeed(speed);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger SetPlaybackSpeed failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::SetTargetStartFrame(const uint64_t targetPts, uint32_t timeoutMs)
{
    MediaTrace trace("LppSyncManagerAdapter::SetTargetStartFrame");
    MEDIA_LOG_I("SetTargetStartFrame enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->SetTargetStartFrame(targetPts, timeoutMs);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger SetTargetStartFrame failed");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::SetParameter(const std::map<std::string, std::string> &parameters)
{
    MediaTrace trace("LppSyncManagerAdapter::SetParameter");
    MEDIA_LOG_I("SetParameter enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->SetParameter(parameters);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger SetParameter failed, ret");
    return MSERR_OK;
}
int32_t LppSyncManagerAdapter::GetParameter(std::map<std::string, std::string> &parameters)
{
    MediaTrace trace("LppSyncManagerAdapter::GetParameter");
    MEDIA_LOG_I("GetParameter enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->GetParameter(parameters);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS && !parameters.empty(), MSERR_VID_RENDER_FAILED,
                       "SyncMananger getParameter failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::UpdateTimeAnchor(const int64_t anchorPts, const int64_t anchorClk)
{
    MediaTrace trace("LppSyncManagerAdapter::UpdateTimeAnchor");
    MEDIA_LOG_I("UpdateTimeAnchor enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    FALSE_RETURN_V_MSG_E(anchorPts >= 0 && anchorClk >= 0, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->UpdateTimeAnchor(static_cast<uint64_t>(anchorPts), static_cast<uint64_t>(anchorClk));
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger UpdateTimeAnchor failed, ret");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::BindOutputBuffers(const std::map<uint32_t, sptr<SurfaceBuffer>> &bufferMap)
{
    MediaTrace trace("LppSyncManagerAdapter::BindOutputBuffers");
    MEDIA_LOG_I("BindOutputBuffers enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    FALSE_RETURN_V_MSG_E(!bufferMap.empty(), MSERR_UNKNOWN, "bufferMap is empty");
    std::map<uint32_t, OHOS::sptr<OHOS::HDI::Base::NativeBuffer>> lppBufferMap;
    for (auto &buffer : bufferMap) {
        if (buffer.second == nullptr) {
            continue;
        }
        MEDIA_LOG_I("SyncMananger BindOutputBuffers sequenceId: %{public}u", buffer.first);
        BufferHandle *bufferHandle = buffer.second->GetBufferHandle();
        lppBufferMap.emplace(buffer.first, new NativeBuffer(bufferHandle));
    }
    int32_t ret = syncMgrAdapter_->BindOutputBuffers(lppBufferMap);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger BindOutputBuffers failed with error");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::UnbindOutputBuffers()
{
    MediaTrace trace("LppSyncManagerAdapter::UnbindOutputBuffers");
    MEDIA_LOG_I("UnbindOutputBuffers enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->UnbindOutputBuffers();
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger BindOutputBuffers failed with error");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::GetShareBuffer(int32_t &fd)
{
    MediaTrace trace("LppSyncManagerAdapter::GetShareBuffer");
    MEDIA_LOG_I("GetShareBuffer enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->GetShareBuffer(fd);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger GetShareBuffer failed with error");
    return MSERR_OK;
}

int32_t LppSyncManagerAdapter::SetTunnelId(uint64_t tunnelId)
{
    MediaTrace trace("LppSyncManagerAdapter::SetTunnelId");
    MEDIA_LOG_I("SetTunnelId enter");
    FALSE_RETURN_V_MSG_E(syncMgrAdapter_ != nullptr, MSERR_UNKNOWN, "syncMgrAdapter_ is nullptr");
    int32_t ret = syncMgrAdapter_->SetTunnelId(tunnelId);
    FALSE_RETURN_V_MSG(ret == HDF_SUCCESS, MSERR_VID_RENDER_FAILED, "SyncMananger SetTunnelId failed with error");
    return MSERR_OK;
}

void LppSyncManagerAdapter::SetEventReceiver(std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver)
{
    eventReceiver_ = eventReceiver;
}

void LppSyncManagerAdapter::OnError(const int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOG_I("OnError: %{public}d", errorCode);
    MediaServiceErrCode msErrCode = HDIErrorToMSError(errorCode);
    if (msErrCode == MSERR_OK) {
        MEDIA_LOG_W("Hardware warning, errorMsg: %{public}s", errorMsg.c_str());
        return;
    }
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    std::pair<MediaServiceErrCode, std::string> errorPair(msErrCode, errorMsg);
    eventReceiver_->OnEvent({"VideoDecoder", EventType::EVENT_ERROR, errorPair});
}

void LppSyncManagerAdapter::OnTargetArrived(const int64_t targetPts, const bool isTimeout)
{
    MEDIA_LOG_I("OnTargetArrived enter");
    MediaTrace trace("LppSyncManagerAdapter::OnTargetArrived");
}

void LppSyncManagerAdapter::OnRenderStarted()
{
    MEDIA_LOG_I("OnRenderStarted enter");
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    eventReceiver_->OnEvent({"VideoDecoder", EventType::EVENT_VIDEO_RENDERING_START, MSERR_OK});
}

void LppSyncManagerAdapter::OnEos()
{
    MEDIA_LOG_I("OnEos enter");
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    eventReceiver_->OnEvent({"VideoDecoder", EventType::EVENT_COMPLETE, MSERR_OK});
}

void LppSyncManagerAdapter::OnInfo(const int32_t infoCode, const std::string &infoMsg)
{
    MEDIA_LOG_W("OnInfo not implement");
}

void LppSyncManagerAdapter::OnFirstFrameReady()
{
    MEDIA_LOG_I("OnFirstFrameReady enter");
    FALSE_RETURN_MSG(eventReceiver_ != nullptr, "eventReceiver_ is nullptr");
    eventReceiver_->OnEvent({"VideoDecoder", EventType::EVENT_FIRST_FRAME_READY, MSERR_OK});
}

int32_t LowPowerPlayerFactory::CreateLppSyncManagerAdapter(uint32_t &instanceId,
    std::shared_ptr<LppSyncManagerAdapter> &adapter)
{
    MediaTrace trace("LowPowerPlayerFactory::CreateLppSyncManagerAdapter");
    MEDIA_LOG_I("CreateLppSyncManagerAdapter enter");
    auto syncAadapter = std::make_unique<LppSyncManagerAdapter>();
    int32_t ret = syncAadapter->LoadAdapter(instanceId);
    FALSE_RETURN_V_MSG(ret == MSERR_OK, MSERR_VID_RENDER_FAILED, "LoadAdapter failed");
    adapter = std::move(syncAadapter);
    return MSERR_OK;
}

int32_t LowPowerPlayerFactory::DestroyLppSyncManagerAdapter(const uint32_t instanceId,
    std::shared_ptr<LppSyncManagerAdapter> adapter)
{
    MediaTrace trace("LowPowerPlayerFactory::DestroyLppSyncManagerAdapter");
    MEDIA_LOG_I("DestroyLppSyncManagerAdapter enter");
    FALSE_RETURN_V_MSG_E(adapter != nullptr, MSERR_INVALID_VAL, "Adapter is nullptr");
    int32_t ret = adapter->UnloadAdapter(instanceId);
    FALSE_RETURN_V_MSG_E(ret == MSERR_OK, ret, "Failed to Destroy LoadAdapter");
    return MSERR_OK;
}

}  // namespace Media
}  // namespace OHOS
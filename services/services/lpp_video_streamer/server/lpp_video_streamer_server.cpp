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

#include "lpp_video_streamer_server.h"

#include "map"
#include "media_log.h"
#include "media_errors.h"
#include "engine_factory_repo.h"
#include "param_wrapper.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "media_dfx.h"
#include "hitrace/tracechain.h"
#include "media_utils.h"
#include "lpp_video_streamer.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppVideoStreamerServer"};
}

namespace OHOS {
namespace Media {
std::map<VideoState, std::set<VideoState>> VIDEO_STATE_TX_MAP = {
    {VideoState::INITIALIZED, {VideoState::CREATED}},
    {VideoState::READY, {VideoState::INITIALIZED, VideoState::PAUSED, VideoState::EOS}},
    {VideoState::DECODING, {VideoState::READY}},
    {VideoState::RENDERING, {VideoState::DECODING, VideoState::PAUSED}},
    {VideoState::PAUSED, {VideoState::RENDERING}},
    {VideoState::EOS, {VideoState::PAUSED, VideoState::DECODING, VideoState::RENDERING}},
    {VideoState::STOPPED, {VideoState::RENDERING, VideoState::PAUSED, VideoState::DECODING, VideoState::READY,
        VideoState::EOS}},
};

std::map<std::string, std::set<VideoState>> VIDEO_FUNC_STATE_CHECK_MAP = {
    {"Flush", {VideoState::PAUSED, VideoState::EOS}},
    {"Prepare", {VideoState::INITIALIZED}},
    {"StartRender", {VideoState::DECODING}},
    {"Resume", {VideoState::PAUSED}},
};

std::shared_ptr<ILppVideoStreamerService> LppVideoStreamerServer::Create()
{
    std::shared_ptr<LppVideoStreamerServer> lppAudioServer = std::make_shared<LppVideoStreamerServer>();
    CHECK_AND_RETURN_RET_LOG(lppAudioServer != nullptr, nullptr, "failed to new LppVideoStreamerServer");
    return lppAudioServer;
}

LppVideoStreamerServer::LppVideoStreamerServer()
{
    appTokenId_ = IPCSkeleton::GetCallingTokenID();
    appUid_ = IPCSkeleton::GetCallingUid();
    appPid_ = IPCSkeleton::GetCallingPid();
    appName_ = GetClientBundleName(appUid_);
}

LppVideoStreamerServer::~LppVideoStreamerServer()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t LppVideoStreamerServer::CreateStreamerEngine()
{
    auto engineFactory =
        EngineFactoryRepo::Instance().GetEngineFactory(IEngineFactory::Scene::SCENE_PLAYBACK, appUid_, appName_);
    CHECK_AND_RETURN_RET_LOG(
        engineFactory != nullptr, MSERR_CREATE_PLAYER_ENGINE_FAILED, "failed to get engine factory");
    streamerEngine_ = engineFactory->CreateLppVideoStreamerEngine(appUid_, appPid_, appTokenId_);
    CHECK_AND_RETURN_RET_LOG(
        streamerEngine_ != nullptr, MSERR_CREATE_PLAYER_ENGINE_FAILED, "failed to create lppVideoStreamer engine");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::Init(const std::string &mime)
{
    MEDIA_LOGD("LppVideoStreamerServer::Init");
    CHECK_AND_RETURN_RET(streamerEngine_ == nullptr, MSERR_OK);
    mime_ = mime;
    auto ret = CreateStreamerEngine();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CreateStreamerEngine failed");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    ret = streamerEngine_->Init(mime);
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Init Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::SetParameter(const Format &param)
{
    MEDIA_LOGD("LppVideoStreamerServer SetParameter");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetParameter(param);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetParameter Failed!");
    param_ = param;
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::GetParameter(Format &param)
{
    MEDIA_LOGI("LppAudioStreamerServer GetParameter");
    param = param_;
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::Configure(const Format &param)
{
    MEDIA_LOGD("LppVideoStreamerServer Configure");
    CHECK_AND_RETURN_RET_LOG(StateEnter(VideoState::INITIALIZED), MSERR_INVALID_OPERATION, "wrong state");
    auto ret = Init(mime_);
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Init Failed!");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    ret = streamerEngine_->Configure(param);
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Configure Failed!");
    param_ = param;
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::Prepare()
{
    MEDIA_LOGI("LppVideoStreamerServer Prepare");
    CHECK_AND_RETURN_RET_LOG(StateEnter(VideoState::READY, "Prepare"), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Prepare();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Prepare Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::Start()
{
    MEDIA_LOGI("LppVideoStreamerServer Start");
    auto ret = MSERR_OK;
    return ret;
}

int32_t LppVideoStreamerServer::StartDecode()
{
    MEDIA_LOGI("LppVideoStreamerServer StartDecode");
    CHECK_AND_RETURN_RET_LOG(StateEnter(VideoState::DECODING), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->StartDecode();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "StartDecode Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::StartRender()
{
    MEDIA_LOGI("LppVideoStreamerServer StartRender");
    CHECK_AND_RETURN_RET_LOG(StateEnter(VideoState::RENDERING, "StartRender"), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->StartRender();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "StartRender Failed!");
    return MSERR_OK;
}


int32_t LppVideoStreamerServer::Pause()
{
    MEDIA_LOGI("LppVideoStreamerServer Pause");
    CHECK_AND_RETURN_RET_LOG(StateEnter(VideoState::PAUSED), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Pause();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Pause Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::Resume()
{
    MEDIA_LOGI("LppVideoStreamerServer Resume");
    CHECK_AND_RETURN_RET_LOG(StateEnter(VideoState::RENDERING, "Resume"), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Resume();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Resume Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::Flush()
{
    MEDIA_LOGI("LppVideoStreamerServer Flush");
    CHECK_AND_RETURN_RET_LOG(StateEnter(VideoState::READY, "Flush"), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Flush();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Flush Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::Stop()
{
    MEDIA_LOGI("LppVideoStreamerServer Stop");
    CHECK_AND_RETURN_RET_LOG(StateEnter(VideoState::STOPPED), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Stop();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Stop Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::Reset()
{
    MEDIA_LOGI("LppVideoStreamerServer Reset");
    Stop();
    CHECK_AND_RETURN_RET_LOG(StateEnter(VideoState::CREATED), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_OK, "streamerEngine_ is nullptr");
    streamerEngine_->Reset();
    streamerEngine_ = nullptr;
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::Release()
{
    MEDIA_LOGI("LppVideoStreamerServer Release");
    Reset();
    StateEnter(VideoState::RELEASED);
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_OK, "streamerEngine_ is nullptr");
    streamerEngine_ = nullptr;
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::SetOutputSurface(sptr<Surface> surface)
{
    MEDIA_LOGI("LppVideoStreamerServer SetOutputSurface");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetVideoSurface(surface);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetOutputSurface Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::SetSyncAudioStreamer(AudioStreamer *audioStreamer)
{
    MEDIA_LOGI("LppVideoStreamerServer SetSyncAudioStreamer");
    (void)audioStreamer;
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::SetTargetStartFrame(const int64_t targetPts, const int timeoutMs)
{
    MEDIA_LOGI("LppVideoStreamerServer SetTargetStartFrame");
    CHECK_AND_RETURN_RET_LOG(StateCheck(VideoState::READY), MSERR_INVALID_OPERATION, "wrong state ");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    streamerEngine_->SetTargetStartFrame(targetPts, timeoutMs);
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::SetVolume(float volume)
{
    MEDIA_LOGI("LppVideoStreamerServer SetVolume");
    (void)volume;
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::SetPlaybackSpeed(float speed)
{
    MEDIA_LOGI("LppVideoStreamerServer SetPlaybackSpeed");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetPlaybackSpeed(speed);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetPlaybackSpeed Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    MEDIA_LOGI("LppVideoStreamerServer ReturnFrames");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    CHECK_AND_RETURN_RET_LOG(framePacket != nullptr, MSERR_INVALID_OPERATION, "framePacket is nullptr");
    auto ret = streamerEngine_->ReturnFrames(framePacket);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "ReturnFrames Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::RegisterCallback()
{
    MEDIA_LOGI("LppVideoStreamerServer RegisterCallback");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetObs(weak_from_this());
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "RegisterCallback Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::SetLppVideoStreamerCallback(const std::shared_ptr<VideoStreamerCallback> &callback)
{
    MEDIA_LOGI("LppVideoStreamerServer SetLppVideoStreamerCallback");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "callback is nullptr");
    callback_ = callback;
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetObs(weak_from_this());
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetLppVideoStreamerCallback Failed!");
    return MSERR_OK;
}

int32_t LppVideoStreamerServer::GetLatestPts(int64_t &pts)
{
    MEDIA_LOGI("LppVideoStreamerServer GetLatestPts");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->GetLatestPts(pts);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "GetLatestPts Failed!");
    return ret;
}

int32_t LppVideoStreamerServer::SetLppAudioStreamerId(const std::string audioStreamId)
{
    MEDIA_LOGI("LppVideoStreamerServer SetLppAudioStreamerId");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetLppAudioStreamerId(audioStreamId);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetLppAudioStreamerId Failed!");
    return MSERR_OK;
}

std::string LppVideoStreamerServer::GetStreamerId()
{
    MEDIA_LOGI("LppVideoStreamerServer::GetStreamerId");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, "", "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->GetStreamerId();
    return ret;
}

int32_t LppVideoStreamerServer::RenderFirstFrame()
{
    MEDIA_LOGI("LppVideoStreamerServer::RenderFirstFrame");
    CHECK_AND_RETURN_RET_LOG(StateCheck(VideoState::DECODING), MSERR_INVALID_OPERATION, "wrong state ");
    CHECK_AND_RETURN_RET_LOG(isFirstFrameDecoded_.load(), MSERR_INVALID_OPERATION, "not first frame");
    CHECK_AND_RETURN_RET_LOG(!isFirstFrameRendered_.load(), MSERR_INVALID_OPERATION, "first frame rendered");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->RenderFirstFrame();
    isFirstFrameRendered_.store(true);
    return ret;
}

bool LppVideoStreamerServer::StateEnter(VideoState targetState, const std::string funcName)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    MEDIA_LOGI("LppVideoStreamerServer::StateEnter state = %{public}d, targetState = %{public}d",
        static_cast<int32_t>(state_), static_cast<int32_t>(targetState));
    auto it = VIDEO_STATE_TX_MAP.find(targetState);
    bool checkPass = (it == VIDEO_STATE_TX_MAP.end()) || (it->second.find(state_) != it->second.end());
    CHECK_AND_RETURN_RET_LOG(checkPass, false, "wrong state, not transcate state");
    auto nameIt = VIDEO_FUNC_STATE_CHECK_MAP.find(funcName);
    checkPass = nameIt == VIDEO_FUNC_STATE_CHECK_MAP.end() || nameIt->second.find(state_) != nameIt->second.end();
    CHECK_AND_RETURN_RET_LOG(checkPass, false, "donnt call this func to transcate state");
    state_ = targetState;
    return true;
}

bool LppVideoStreamerServer::StateCheck(VideoState curState)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    return state_ == curState;
}

bool LppVideoStreamerServer::ErrorCheck(int32_t errorCode)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (errorCode != MSERR_OK) {
        state_ = VideoState::ERROR;
        return false;
    }
    return true;
}

void LppVideoStreamerServer::OnDataNeeded(const int32_t maxBufferSize, const int32_t maxFrameNum)
{
    MEDIA_LOGD("LppVideoStreamerServer OnDataNeeded");
    Format infoBody;
    infoBody.PutIntValue(VideoStreamerKeys::LPP_VIDEO_MAX_BUFFER_SIZE, maxBufferSize);
    infoBody.PutIntValue(VideoStreamerKeys::LPP_VIDEO_MAX_FRAME_NUM, maxFrameNum);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ nullptr");
    callback_->OnInfo(VIDEO_INFO_TYPE_LPP_DATA_NEEDED, 0, infoBody);
}

bool LppVideoStreamerServer::OnAnchorUpdateNeeded(int64_t &anchorPts, int64_t &anchorClk)
{
    MEDIA_LOGI("LppVideoStreamerServer::OnAnchorUpdateNeeded Anchor update needed");
    return false;
}

void LppVideoStreamerServer::OnError(const MediaServiceErrCode errCode, const std::string &errMsg)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    MEDIA_LOGE("LppVideoStreamerServer::OnError, errorCode: %{public}d, errorMsg: %{public}s",
        static_cast<int32_t>(errCode), errMsg.c_str());
    StateEnter(VideoState::ERROR);
    callback_->OnError(static_cast<int32_t>(errCode), errMsg);
}

void LppVideoStreamerServer::OnEos()
{
    MEDIA_LOGI("LppVideoStreamerServer::OnEos");
    CHECK_AND_RETURN_LOG(StateEnter(VideoState::EOS), "wrong state");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    Format infoBody;
    callback_->OnInfo(VIDEO_INFO_TYPE_LPP_EOS, 0, infoBody);
}

void LppVideoStreamerServer::OnRenderStarted()
{
    MEDIA_LOGI("LppVideoStreamerServer::OnRenderStarted Render started");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    Format infoBody;
    callback_->OnInfo(VIDEO_INFO_TYPE_LPP_RENDER_STARTED, 0, infoBody);
}

void LppVideoStreamerServer::OnTargetArrived(const int64_t targetPts, const bool isTimeout)
{
    MEDIA_LOGI("LppVideoStreamerServer::OnTargetArrived Target arrived");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    Format infoBody;
    infoBody.PutLongValue(VideoStreamerKeys::LPP_VIDEO_TARGET_PTS, targetPts);
    infoBody.PutIntValue(VideoStreamerKeys::LPP_VIDEO_IS_TIMEOUT, isTimeout);
    callback_->OnInfo(VIDEO_INFO_TYPE_LPP_TARGET_ARRIVED, 0, infoBody);
}

void LppVideoStreamerServer::OnFirstFrameReady()
{
    MEDIA_LOGI("LppVideoStreamerServer::First frame ready");
    CHECK_AND_RETURN_LOG(!isFirstFrameDecoded_.load(), "first frame is decoded, dont repeat");
    isFirstFrameDecoded_.store(true);
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    Format infoBody;
    callback_->OnInfo(VIDEO_INFO_TYPE_LPP_FIRST_FRAME_READY, 0, infoBody);
}

void LppVideoStreamerServer::OnStreamChanged(Format &format)
{
    MEDIA_LOGI("LppVideoStreamerServer::OnStreamChanged");
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
    callback_->OnInfo(VIDEO_INFO_TYPE_LPP_STREAM_CHANGED, 0, format);
}
}  // namespace Media
}  // namespace OHOS

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

#include "lpp_audio_streamer_server.h"

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
#include "lpp_audio_streamer.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppAudioStreamerServer"};
constexpr float MAX_LOUDNESS_GAIN = 24.0f;
constexpr float MIN_LOUDNESS_GAIN = -90.0f;
}

namespace OHOS {
namespace Media {

std::map<LppAudioState, std::set<LppAudioState>> AUDIO_STATE_TX_MAP = {
    {LppAudioState::INITIALIZED, {LppAudioState::CREATED}},
    {LppAudioState::READY, {LppAudioState::INITIALIZED, LppAudioState::PAUSED, LppAudioState::EOS}},
    {LppAudioState::STARTING, {LppAudioState::READY, LppAudioState::PAUSED}},
    {LppAudioState::PAUSED, {LppAudioState::STARTING}},
    {LppAudioState::EOS, {LppAudioState::PAUSED, LppAudioState::STARTING}},
    {LppAudioState::STOPPED, {LppAudioState::STARTING, LppAudioState::PAUSED,
        LppAudioState::READY, LppAudioState::EOS}},
};

std::map<std::string, std::set<LppAudioState>> AUDIO_FUNC_STATE_CHECK_MAP = {
    {"Flush", {LppAudioState::PAUSED, LppAudioState::EOS}},
    {"Prepare", {LppAudioState::INITIALIZED}},
    {"Start", {LppAudioState::READY}},
    {"Resume", {LppAudioState::PAUSED}},
};

std::shared_ptr<ILppAudioStreamerService> LppAudioStreamerServer::Create()
{
    std::shared_ptr<LppAudioStreamerServer> lppAudioServer = std::make_shared<LppAudioStreamerServer>();
    CHECK_AND_RETURN_RET_LOG(lppAudioServer != nullptr, nullptr, "failed to new LppAudioStreamerServer");
    return lppAudioServer;
}

LppAudioStreamerServer::LppAudioStreamerServer()
{
    appTokenId_ = IPCSkeleton::GetCallingTokenID();
    appUid_ = IPCSkeleton::GetCallingUid();
    appPid_ = IPCSkeleton::GetCallingPid();
    appName_ = GetClientBundleName(appUid_);
}

LppAudioStreamerServer::~LppAudioStreamerServer()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t LppAudioStreamerServer::CreateStreamerEngine()
{
    auto engineFactory =
        EngineFactoryRepo::Instance().GetEngineFactory(IEngineFactory::Scene::SCENE_PLAYBACK, appUid_, appName_);
    CHECK_AND_RETURN_RET_LOG(
        engineFactory != nullptr, MSERR_CREATE_PLAYER_ENGINE_FAILED, "failed to get engine factory");
    streamerEngine_ = engineFactory->CreateLppAudioStreamerEngine(appUid_, appPid_, appTokenId_);
    CHECK_AND_RETURN_RET_LOG(
        streamerEngine_ != nullptr, MSERR_CREATE_PLAYER_ENGINE_FAILED, "failed to create lppAudioStreamer engine");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Init(const std::string &mime)
{
    MEDIA_LOGI("LppAudioStreamerServer::Init");
    CHECK_AND_RETURN_RET(streamerEngine_ == nullptr, MSERR_OK);
    mime_ = mime;
    auto ret = CreateStreamerEngine();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CreateStreamerEngine Failed!");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    ret = streamerEngine_->Init(mime);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "Init Failed!");
    return ret;
}

int32_t LppAudioStreamerServer::SetLppVideoStreamerId(const std::string videoStreamId)
{
    MEDIA_LOGI("LppAudioStreamerServer SetLppVideoStreamerId");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetLppVideoStreamerId(videoStreamId);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetLppVideoStreamerId Failed!");
    return MSERR_OK;
}

std::string LppAudioStreamerServer::GetStreamerId()
{
    MEDIA_LOGI("LppAudioStreamerServer::GetStreamerId");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, "", "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->GetStreamerId();
    return ret;
}

int32_t LppAudioStreamerServer::SetParameter(const Format &param)
{
    MEDIA_LOGI("LppAudioStreamerServer SetParameter");
    (void)param;
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::GetParameter(Format &param)
{
    MEDIA_LOGI("LppAudioStreamerServer GetParameter");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    param = param_;
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Configure(const Format &param)
{
    MEDIA_LOGI("LppAudioStreamerServer Configure");
    CHECK_AND_RETURN_RET_LOG(StateEnter(LppAudioState::INITIALIZED), MSERR_INVALID_OPERATION, "wrong state");
    auto ret = Init(mime_);
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Init Failed!");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    ret = streamerEngine_->Configure(param);
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "SetParameter Failed!");
    param_ = param;
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Prepare()
{
    MEDIA_LOGI("LppAudioStreamerServer Prepare");
    CHECK_AND_RETURN_RET_LOG(StateEnter(LppAudioState::READY, "Prepare"), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Prepare();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Prepare Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Start()
{
    MEDIA_LOGI("LppAudioStreamerServer Start");
    CHECK_AND_RETURN_RET_LOG(StateEnter(LppAudioState::STARTING, "Start"), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Start();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Start Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Pause()
{
    MEDIA_LOGI("LppAudioStreamerServer Pause");
    CHECK_AND_RETURN_RET_LOG(StateEnter(LppAudioState::PAUSED), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Pause();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Pause Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Resume()
{
    MEDIA_LOGI("LppAudioStreamerServer Resume");
    CHECK_AND_RETURN_RET_LOG(StateEnter(LppAudioState::STARTING, "Resume"), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Resume();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Resume Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Flush()
{
    MEDIA_LOGI("LppAudioStreamerServer Flush");
    CHECK_AND_RETURN_RET_LOG(StateEnter(LppAudioState::READY, "Flush"), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Flush();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Flush Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Stop()
{
    MEDIA_LOGI("LppAudioStreamerServer Stop");
    CHECK_AND_RETURN_RET_LOG(StateEnter(LppAudioState::STOPPED), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Stop();
    CHECK_AND_RETURN_RET_LOG(ErrorCheck(ret), ret, "Stop Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Reset()
{
    MEDIA_LOGI("LppAudioStreamerServer Reset");
    CHECK_AND_RETURN_RET_LOG(StateEnter(LppAudioState::CREATED), MSERR_INVALID_OPERATION, "wrong state");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->Reset();
    streamerEngine_ = nullptr;
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "Reset Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::Release()
{
    MEDIA_LOGI("LppAudioStreamerServer Release");
    StateEnter(LppAudioState::RELEASED);
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_OK, "streamerEngine_ is nullptr");
    streamerEngine_ = nullptr;
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::SetVolume(float volume)
{
    MEDIA_LOGI("LppAudioStreamerServer SetVolume");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetVolume(volume);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetVolume Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::SetLoudnessGain(const float loudnessGain)
{
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        CHECK_AND_RETURN_RET_LOG(state_ != LppAudioState::ERROR && state_ != LppAudioState::RELEASED,
            MSERR_INVALID_OPERATION,
            "wrong state");
    }
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    if ((loudnessGain < MIN_LOUDNESS_GAIN) || (loudnessGain > MAX_LOUDNESS_GAIN)) {
        MEDIA_LOGE("SetLoudnessGain failed, the loudnessGain should be set to a value ranging from -90 to 24");
        return MSERR_INVALID_OPERATION;
    }
    auto ret = streamerEngine_->SetLoudnessGain(loudnessGain);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "loudnessGain Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::SetPlaybackSpeed(float speed)
{
    MEDIA_LOGI("LppAudioStreamerServer SetPlaybackSpeed");
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetPlaybackSpeed(speed);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetPlaybackSpeed Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    CHECK_AND_RETURN_RET_LOG(framePacket != nullptr, MSERR_INVALID_VAL, "framePacket is nullptr");
    auto ret = streamerEngine_->ReturnFrames(framePacket);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "ReturnFrames Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::RegisterCallback()
{
    MEDIA_LOGI("LppAudioStreamerServer RegisterCallback");
    std::shared_ptr<ILppAudioStreamerEngineObs> obs = shared_from_this();
    CHECK_AND_RETURN_RET_LOG(streamerEngine_ != nullptr, MSERR_INVALID_OPERATION, "streamerEngine_ is nullptr");
    auto ret = streamerEngine_->SetObs(obs);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "RegisterCallback Failed!");
    return MSERR_OK;
}

int32_t LppAudioStreamerServer::SetLppAudioStreamerCallback(const std::shared_ptr<AudioStreamerCallback> &callback)
{
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "callback nullptr");
    lppAudioStreamerCb_ = callback;
    return MSERR_OK;
}

bool LppAudioStreamerServer::StateEnter(LppAudioState targetState, const std::string funcName)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    MEDIA_LOGI("LppAudioStreamerServer::StateEnter state = %{public}d, targetState = %{public}d",
        static_cast<int32_t>(state_), static_cast<int32_t>(targetState));
    auto it = AUDIO_STATE_TX_MAP.find(targetState);
    bool checkPass = (it == AUDIO_STATE_TX_MAP.end()) || (it->second.find(state_) != it->second.end());
    CHECK_AND_RETURN_RET_LOG(checkPass, false, "wrong state, not transcate state");
    auto nameIt = AUDIO_FUNC_STATE_CHECK_MAP.find(funcName);
    checkPass = nameIt == AUDIO_FUNC_STATE_CHECK_MAP.end() || nameIt->second.find(state_) != nameIt->second.end();
    CHECK_AND_RETURN_RET_LOG(checkPass, false, "donnt call this func to transcate state");
    state_ = targetState;
    return true;
}

bool LppAudioStreamerServer::StateCheck(LppAudioState curState)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    return state_ == curState;
}

bool LppAudioStreamerServer::ErrorCheck(int32_t errorCode)
{
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (errorCode != MSERR_OK) {
        state_ = LppAudioState::ERROR;
        return false;
    }
    return true;
}

void LppAudioStreamerServer::OnError(const MediaServiceErrCode errCode, const std::string &errMsg)
{
    CHECK_AND_RETURN_LOG(lppAudioStreamerCb_ != nullptr, "lppAudioStreamerCb_ nullptr");
    MEDIA_LOGE("LppAudioStreamerServer::OnError, errorCode: %{public}d, errorMsg: %{public}s",
        static_cast<int32_t>(errCode), errMsg.c_str());
    StateEnter(LppAudioState::ERROR);
    lppAudioStreamerCb_->OnError(static_cast<int32_t>(errCode), errMsg);
}

void LppAudioStreamerServer::OnDataNeeded(const int32_t maxBufferSize)
{
    CHECK_AND_RETURN_LOG(lppAudioStreamerCb_ != nullptr, "lppAudioStreamerCb_ nullptr");
    MEDIA_LOGI("LppAudioStreamerServer::OnDataNeeded %{public}d", maxBufferSize);
    Format infoBody;
    infoBody.PutIntValue(AudioStreamerKeys::LPP_AUDIO_MAX_BUFFER_SIZE, maxBufferSize);
    infoBody.PutIntValue(AudioStreamerKeys::LPP_AUDIO_MAX_FRAME_NUM, maxBufferSize);
    lppAudioStreamerCb_->OnInfo(INFO_TYPE_LPP_AUDIO_DATA_NEEDED, 0, infoBody);
}

void LppAudioStreamerServer::OnPositionUpdated(const int64_t currentPositionMs)
{
    CHECK_AND_RETURN_LOG(lppAudioStreamerCb_ != nullptr, "lppAudioStreamerCb_ nullptr");
    MEDIA_LOGI("LppAudioStreamerServer::OnPositionUpdated %{public}ld", currentPositionMs);
    Format infoBody;
    infoBody.PutLongValue(AudioStreamerKeys::LPP_CURRENT_POSITION, currentPositionMs);
    lppAudioStreamerCb_->OnInfo(INFO_TYPE_LPP_AUDIO_POSITION_UPDATE, 0, infoBody);
}

void LppAudioStreamerServer::OnEos()
{
    MEDIA_LOGI("LppAudioStreamerServer::OnEos");
    CHECK_AND_RETURN_LOG(StateEnter(LppAudioState::EOS), "wrong state");
    CHECK_AND_RETURN_LOG(lppAudioStreamerCb_ != nullptr, "lppAudioStreamerCb_ nullptr");
    Format infoBody;
    lppAudioStreamerCb_->OnInfo(INFO_TYPE_LPP_AUDIO_EOS, 0, infoBody);
}

void LppAudioStreamerServer::OnInterrupted(const int64_t forceType, const int64_t hint)
{
    CHECK_AND_RETURN_LOG(lppAudioStreamerCb_ != nullptr, "lppAudioStreamerCb_ nullptr");
    MEDIA_LOGI("LppAudioStreamerServer::OnInterrupted forceType %{public}ld hint %{public}ld", forceType, hint);
    Format infoBody;
    infoBody.PutLongValue(AudioStreamerKeys::LPP_AUDIO_INTERRUPT_FORCE_TYPE, forceType);
    infoBody.PutLongValue(AudioStreamerKeys::LPP_AUDIO_INTERRUPT_HINT, hint);
    lppAudioStreamerCb_->OnInfo(INFO_TYPE_LPP_AUDIO_INTERRUPT, 0, infoBody);
}

void LppAudioStreamerServer::OnDeviceChanged(const int64_t reason)
{
    CHECK_AND_RETURN_LOG(lppAudioStreamerCb_ != nullptr, "lppAudioStreamerCb_ nullptr");
    MEDIA_LOGI("LppAudioStreamerServer::OnDeviceChanged reason %{public}ld", reason);
    Format infoBody;
    infoBody.PutLongValue(AudioStreamerKeys::LPP_AUDIO_DEVICE_CHANGE_REASON, reason);
    lppAudioStreamerCb_->OnInfo(INFO_TYPE_LPP_AUDIO_DEVICE_CHANGE, 0, infoBody);
}

}  // namespace Media
}  // namespace OHOS

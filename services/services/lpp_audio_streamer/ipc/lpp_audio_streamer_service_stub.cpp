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

#include "lpp_audio_streamer_service_stub.h"
#include <unistd.h>
#include "media_data_source_proxy.h"
#include "media_server_manager.h"
#include "lpp_audio_streamer_listener_proxy.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"
#include "parameter.h"
#include "media_dfx.h"
#include "player_xcollie.h"
#include "av_common.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppAudioStreamerServiceStub"};
}

namespace OHOS {
namespace Media {
sptr<LppAudioStreamerServiceStub> LppAudioStreamerServiceStub::Create()
{
    sptr<LppAudioStreamerServiceStub> playerStub = new (std::nothrow) LppAudioStreamerServiceStub();
    CHECK_AND_RETURN_RET_LOG(playerStub != nullptr, nullptr, "failed to new LppAudioStreamerServiceStub");

    int32_t ret = playerStub->Init();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to player stub init");
    return playerStub;
}

LppAudioStreamerServiceStub::LppAudioStreamerServiceStub()
    : taskQue_("LppAudioStreamerRequest")
{
    (void)taskQue_.Start();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

LppAudioStreamerServiceStub::~LppAudioStreamerServiceStub()
{
    std::lock_guard<std::mutex> lock(aServiceStubMutex_);
    if (lppAudioPlayerServer_ != nullptr) {
        auto task = std::make_shared<TaskHandler<void>>([this] {
            (void)lppAudioPlayerServer_->Release();
            lppAudioPlayerServer_ = nullptr;
        });
        (void)taskQue_.EnqueueTask(task);
        (void)task->GetResult();
    }
    (void)taskQue_.Stop();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t LppAudioStreamerServiceStub::Init()
{
    {
        std::lock_guard<std::mutex> lock(aServiceStubMutex_);
        if (lppAudioPlayerServer_ == nullptr) {
            lppAudioPlayerServer_ = LppAudioStreamerServer::Create();
        }
        CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_NO_MEMORY,"failed to create lppAudioStreamerServer_");
        if (framePacket_ == nullptr) {
            framePacket_ = OHOS::sptr<LppDataPacket>::MakeSptr();
            CHECK_AND_RETURN_RET_LOG(framePacket_ != nullptr, MSERR_NO_MEMORY, "failed to create framePacket_");
        }
    }
    SetPlayerFuncs();
    return MSERR_OK;
}

void LppAudioStreamerServiceStub::SetPlayerFuncs()
{
    FillPlayerFuncPart1();
}

void LppAudioStreamerServiceStub::FillPlayerFuncPart1()
{
    playerFuncs_[INIT] = {"Player::Init",
        [this](MessageParcel &data, MessageParcel &reply) { return Init(data, reply); }};
    playerFuncs_[SET_PARAMETER] = {"Player::SetParameter",
        [this](MessageParcel &data, MessageParcel &reply) { return SetParameter(data, reply); }};
    playerFuncs_[CONFIGURE] = {
        "Player::Configure", [this](MessageParcel &data, MessageParcel &reply) { return Configure(data, reply); }};
    playerFuncs_[PREPARE] = {
        "Player::Prepare", [this](MessageParcel &data, MessageParcel &reply) { return Prepare(data, reply); }};
    playerFuncs_[START] = {
        "Player::Start", [this](MessageParcel &data, MessageParcel &reply) { return Start(data, reply); }};
    playerFuncs_[PAUSE] = {
        "Player::Pause", [this](MessageParcel &data, MessageParcel &reply) { return Pause(data, reply); }};
    playerFuncs_[RESUME] = {
        "Player::Resume", [this](MessageParcel &data, MessageParcel &reply) { return Resume(data, reply); }};
    playerFuncs_[FLUSH] = {
        "Player::Flush", [this](MessageParcel &data, MessageParcel &reply) { return Flush(data, reply); }};
    playerFuncs_[STOP] = {
        "Player::Stop", [this](MessageParcel &data, MessageParcel &reply) { return Stop(data, reply); }};
    playerFuncs_[RESET] = {
        "Player::Reset", [this](MessageParcel &data, MessageParcel &reply) { return Reset(data, reply); }};
    playerFuncs_[RELEASE] = {
        "Player::Release", [this](MessageParcel &data, MessageParcel &reply) { return Release(data, reply); }};
    playerFuncs_[SET_VOLUME] = {
        "Player::SetVolume", [this](MessageParcel &data, MessageParcel &reply) { return SetVolume(data, reply); }};
    playerFuncs_[SET_PLAYBACK_SPEED] = {"Player::SetPlaybackSpeed",
        [this](MessageParcel &data, MessageParcel &reply) { return SetPlaybackSpeed(data, reply); }};
    playerFuncs_[RETURN_FRAMES] = {"Player::ReturnFrames",
        [this](MessageParcel &data, MessageParcel &reply) { return ReturnFrames(data, reply); }};
    playerFuncs_[REGISTER_CALLBACK] = {"Player::RegisterCallback",
        [this](MessageParcel &data, MessageParcel &reply) { return RegisterCallback(data, reply); }};
    playerFuncs_[SET_AUDIO_STREAM_CALLBACK] = {"Player::SetLppAudioStreamerCallback",
        [this](MessageParcel &data, MessageParcel &reply) { return SetLppAudioStreamerCallback(data, reply); }};
    playerFuncs_[SET_LISTENER_OBJ] = {"Player::SetListenerObject",
        [this](MessageParcel &data, MessageParcel &reply) { return SetListenerObject(data, reply); }};
    playerFuncs_[SET_VIDOE_STREAMER_ID] = {"Player::SetLppVideoStreamerId",
        [this](MessageParcel &data, MessageParcel &reply) { return SetLppVideoStreamerId(data, reply); }};
    playerFuncs_[GET_STREAM_ID] = {"Player::GetStreamerId",
        [this](MessageParcel &data, MessageParcel &reply) { return GetStreamerId(data, reply); }};
    playerFuncs_[SET_LOUDNESS_GAIN] = {"Player::SetLoudnessGain",
        [this](MessageParcel &data, MessageParcel &reply) { return SetLoudnessGain(data, reply); }};
}

int LppAudioStreamerServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    MEDIA_LOGD(
        "0x%{public}06" PRIXPTR " Stub: OnRemoteRequest of code: %{public}u is received", FAKE_POINTER(this), code);

    auto remoteDescriptor = data.ReadInterfaceToken();
    if (LppAudioStreamerServiceStub::GetDescriptor() != remoteDescriptor) {
        MEDIA_LOGE("Invalid descriptor");
        return MSERR_INVALID_OPERATION;
    }
    auto itFunc = playerFuncs_.find(code);
    if (itFunc != playerFuncs_.end()) {
        auto memberFunc = itFunc->second.second;
        auto funcName = itFunc->second.first;
        if (memberFunc != nullptr) {
            std::lock_guard<std::mutex> lock(aServiceStubMutex_);
            auto task = std::make_shared<TaskHandler<int>>([&memberFunc, &data, &reply, &funcName] {
                MediaTrace trace(funcName);
                return memberFunc(data, reply);
            });
            (void)taskQue_.EnqueueTask(task);
            auto result = task->GetResult();
            CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION,
                "failed to OnRemoteRequest code: %{public}u", code);
            return result.Value();
        }
    }
    MEDIA_LOGW("playerFuncs_: no member func supporting, applying default process");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t LppAudioStreamerServiceStub::Init(const std::string &mime)
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->Init(mime);
}

int32_t LppAudioStreamerServiceStub::Init(MessageParcel &data, MessageParcel &reply)
{
    std::string mime = data.ReadString();

    reply.WriteInt32(Init(mime));

    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::SetParameter(const Format &param)
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->SetParameter(param);
}

int32_t LppAudioStreamerServiceStub::SetParameter(MessageParcel &data, MessageParcel &reply)
{
    Format param;
    bool ret = MediaParcel::MetaUnmarshalling(data, param);
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_INVALID_OPERATION, "Failed to get format from parcel!");

    reply.WriteInt32(SetParameter(param));

    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Configure(const Format &param)
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->Configure(param);
}

int32_t LppAudioStreamerServiceStub::Configure(MessageParcel &data, MessageParcel &reply)
{
    Format param;
    bool ret = MediaParcel::MetaUnmarshalling(data, param);
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_INVALID_OPERATION, "Failed to get format from parcel!");

    reply.WriteInt32(Configure(param));

    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Prepare()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->Prepare();
}

int32_t LppAudioStreamerServiceStub::Prepare(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Prepare());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Start()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->Start();
}

int32_t LppAudioStreamerServiceStub::Start(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Start());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Pause()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->Pause();
}

int32_t LppAudioStreamerServiceStub::Pause(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Pause());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Resume()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->Resume();
}

int32_t LppAudioStreamerServiceStub::Resume(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Resume());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Flush()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->Flush();
}

int32_t LppAudioStreamerServiceStub::Flush(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Flush());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Stop()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->Stop();
}

int32_t LppAudioStreamerServiceStub::Stop(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Stop());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Reset()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->Reset();
}

int32_t LppAudioStreamerServiceStub::Reset(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Reset());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Release()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    lppAudioPlayerServer_->Release();
    lppAudioPlayerServer_ = nullptr;
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::Release(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Release());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::SetVolume(float volume)
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->SetVolume(volume);
}

int32_t LppAudioStreamerServiceStub::SetVolume(MessageParcel &data, MessageParcel &reply)
{
    float volume = data.ReadFloat();
    reply.WriteInt32(SetVolume(volume));
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::SetLoudnessGain(const float loudnessGain)
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->SetLoudnessGain(loudnessGain);
}

int32_t LppAudioStreamerServiceStub::SetLoudnessGain(MessageParcel &data, MessageParcel &reply)
{
    float loudnessGain = data.ReadFloat();
    reply.WriteInt32(SetLoudnessGain(loudnessGain));
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::SetPlaybackSpeed(float speed)
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->SetPlaybackSpeed(speed);
}

int32_t LppAudioStreamerServiceStub::SetPlaybackSpeed(MessageParcel &data, MessageParcel &reply)
{
    float speed = data.ReadFloat();
    reply.WriteInt32(SetPlaybackSpeed(speed));
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->ReturnFrames(framePacket);
}

int32_t LppAudioStreamerServiceStub::ReturnFrames(MessageParcel &data, MessageParcel &reply)
{
    framePacket_->Clear();
    framePacket_->ReadFromMessageParcel(data);
    reply.WriteInt32(ReturnFrames(framePacket_));
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::RegisterCallback()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->RegisterCallback();
}

int32_t LppAudioStreamerServiceStub::RegisterCallback(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(RegisterCallback());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::SetListenerObject(const sptr<IRemoteObject> &object)
{
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "set listener object is nullptr");

    sptr<IStandardLppAudioStreamerListener> listener = iface_cast<IStandardLppAudioStreamerListener>(object);
    CHECK_AND_RETURN_RET_LOG(
        listener != nullptr, MSERR_NO_MEMORY, "failed to convert IStandardLppAudioStreamerListener");

    std::shared_ptr<AudioStreamerCallback> callback = std::make_shared<LppAudioStreamerListenerCallback>(listener);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_NO_MEMORY, "failed to new LppAudioStreamListenerCallback");
    playerCallback_ = callback;
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::SetListenerObject(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    reply.WriteInt32(SetListenerObject(object));
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::SetLppAudioStreamerCallback()
{
    MEDIA_LOGD("SetLppAudioStreamerCallback");
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION,
        "lppaudioplayer server is nullptr");
    return lppAudioPlayerServer_->SetLppAudioStreamerCallback(playerCallback_);
}

int32_t LppAudioStreamerServiceStub::SetLppAudioStreamerCallback(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(SetLppAudioStreamerCallback());
    return MSERR_OK;
}

int32_t LppAudioStreamerServiceStub::SetLppVideoStreamerId(std::string videoStreamerId)
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppAudioPlayerServer_->SetLppVideoStreamerId(videoStreamerId);
}

int32_t LppAudioStreamerServiceStub::SetLppVideoStreamerId(MessageParcel &data, MessageParcel &reply)
{
    std::string videoStreamerId = data.ReadString();
    reply.WriteInt32(SetLppVideoStreamerId(videoStreamerId));
    return MSERR_OK;
}

std::string LppAudioStreamerServiceStub::GetStreamerId()
{
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerServer_ != nullptr, "", "player server is nullptr");
    return lppAudioPlayerServer_->GetStreamerId();
}

int32_t LppAudioStreamerServiceStub::GetStreamerId(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteString(GetStreamerId());
    return MSERR_OK;
}

}  // namespace Media
}  // namespace OHOS

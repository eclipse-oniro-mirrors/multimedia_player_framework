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

#include "lpp_video_streamer_service_stub.h"
#include <unistd.h>
#include "media_data_source_proxy.h"
#include "media_server_manager.h"
#include "lpp_video_streamer_listener_proxy.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"
#include "parameter.h"
#include "media_dfx.h"
#include "player_xcollie.h"
#include "av_common.h"
#include "lpp_audio_streamer.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppVideoStreamerServiceStub"};
}

namespace OHOS {
namespace Media {
sptr<LppVideoStreamerServiceStub> LppVideoStreamerServiceStub::Create()
{
    sptr<LppVideoStreamerServiceStub> playerStub = new (std::nothrow) LppVideoStreamerServiceStub();
    CHECK_AND_RETURN_RET_LOG(playerStub != nullptr, nullptr, "failed to new LppVideoStreamerServiceStub");

    int32_t ret = playerStub->Init();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to player stub init");
    return playerStub;
}

LppVideoStreamerServiceStub::LppVideoStreamerServiceStub()
    : taskQue_("LppAudioStreamerRequest")
{
    (void)taskQue_.Start();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

LppVideoStreamerServiceStub::~LppVideoStreamerServiceStub()
{
    std::lock_guard<std::mutex> lock(vServiceStubMutex_);
    if (lppVideoPlayerServer_ != nullptr) {
        auto task = std::make_shared<TaskHandler<void>>([this] {
            (void)lppVideoPlayerServer_->Release();
            lppVideoPlayerServer_ = nullptr;
        });
        (void)taskQue_.EnqueueTask(task);
        (void)task->GetResult();
    }
    (void)taskQue_.Stop();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t LppVideoStreamerServiceStub::Init()
{
    {
        std::lock_guard<std::mutex> lock(vServiceStubMutex_);
        if (lppVideoPlayerServer_ == nullptr) {
            lppVideoPlayerServer_ = LppVideoStreamerServer::Create();
        }
        CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_NO_MEMORY,"failed to create lppVideoPlayerServer_");
        if (framePacket_ == nullptr) {
            framePacket_ = OHOS::sptr<LppDataPacket>::MakeSptr();
            CHECK_AND_RETURN_RET_LOG(framePacket_ != nullptr, MSERR_NO_MEMORY, "failed to create framePacket_");
        }
    }
    SetPlayerFuncs();
    return MSERR_OK;
}

void LppVideoStreamerServiceStub::SetPlayerFuncs()
{
    FillPlayerFuncPart1();
    FillPlayerFuncPart2();
}

void LppVideoStreamerServiceStub::FillPlayerFuncPart1()
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
    playerFuncs_[SET_AUDIO_STREAM_CALLBACK] = {"Player::SetLppVideoStreamerCallback",
        [this](MessageParcel &data, MessageParcel &reply) { return SetLppVideoStreamerCallback(data, reply); }};
    playerFuncs_[SET_LISTENER_OBJ] = {"Player::SetListenerObject",
        [this](MessageParcel &data, MessageParcel &reply) { return SetListenerObject(data, reply); }};
    playerFuncs_[START_DECODE] = {
        "Player::StartDecode", [this](MessageParcel &data, MessageParcel &reply) { return StartDecode(data, reply); }};
    playerFuncs_[START_RENDER] = {
        "Player::StartRender", [this](MessageParcel &data, MessageParcel &reply) { return StartRender(data, reply); }};
    playerFuncs_[SET_TARGET_START_FRAME] = {"Player::SetTargetStartFrame",
        [this](MessageParcel &data, MessageParcel &reply) { return SetTargetStartFrame(data, reply); }};
    playerFuncs_[SET_OUTPUT_SURFACE] = {"Player::SetOutputSurface",
        [this](MessageParcel &data, MessageParcel &reply) { return SetOutputSurface(data, reply); }};
    playerFuncs_[SET_AUDIO_STREAMER_ID] = {"Player::SetLppAudioStreamerId",
        [this](MessageParcel &data, MessageParcel &reply) { return SetLppAudioStreamerId(data, reply); }};
    playerFuncs_[GET_STREAM_ID] = {"Player::GetStreamerId",
        [this](MessageParcel &data, MessageParcel &reply) { return GetStreamerId(data, reply); }};
    playerFuncs_[RENDER_FIRST_FRAME] = {"Player::RenderFirstFrame",
        [this](MessageParcel &data, MessageParcel &reply) { return RenderFirstFrame(data, reply); }};
}

void LppVideoStreamerServiceStub::FillPlayerFuncPart2()
{
    playerFuncs_[GET_LATEST_PTS] = {"Player::GetLatestPts",
        [this](MessageParcel &data, MessageParcel &reply) { return GetLatestPts(data, reply); }};
}

int LppVideoStreamerServiceStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    MEDIA_LOGD(
        "0x%{public}06" PRIXPTR " Stub: OnRemoteRequest of code: %{public}u is received", FAKE_POINTER(this), code);

    auto remoteDescriptor = data.ReadInterfaceToken();
    if (LppVideoStreamerServiceStub::GetDescriptor() != remoteDescriptor) {
        MEDIA_LOGE("Invalid descriptor");
        return MSERR_INVALID_OPERATION;
    }
    auto itFunc = playerFuncs_.find(code);
    if (itFunc != playerFuncs_.end()) {
        auto memberFunc = itFunc->second.second;
        auto funcName = itFunc->second.first;
        if (memberFunc != nullptr) {
            std::lock_guard<std::mutex> lock(vServiceStubMutex_);
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

int32_t LppVideoStreamerServiceStub::Init(const std::string &mime)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->Init(mime);
}

int32_t LppVideoStreamerServiceStub::Init(MessageParcel &data, MessageParcel &reply)
{
    std::string mime = data.ReadString();
    reply.WriteInt32(Init(mime));
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetParameter(const Format &param)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->SetParameter(param);
}

int32_t LppVideoStreamerServiceStub::SetParameter(MessageParcel &data, MessageParcel &reply)
{
    Format param;
    (void)MediaParcel::Unmarshalling(data, param);

    reply.WriteInt32(SetParameter(param));

    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Configure(const Format &param)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->Configure(param);
}

int32_t LppVideoStreamerServiceStub::Configure(MessageParcel &data, MessageParcel &reply)
{
    Format param;
    (void)MediaParcel::Unmarshalling(data, param);

    reply.WriteInt32(Configure(param));

    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Prepare()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->Prepare();
}

int32_t LppVideoStreamerServiceStub::Prepare(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Prepare());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Start()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->Start();
}

int32_t LppVideoStreamerServiceStub::Start(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Start());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Pause()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->Pause();
}

int32_t LppVideoStreamerServiceStub::Pause(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Pause());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Resume()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->Resume();
}

int32_t LppVideoStreamerServiceStub::Resume(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Resume());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Flush()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->Flush();
}

int32_t LppVideoStreamerServiceStub::Flush(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Flush());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Stop()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->Stop();
}

int32_t LppVideoStreamerServiceStub::Stop(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Stop());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Reset()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->Reset();
}

int32_t LppVideoStreamerServiceStub::Reset(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Reset());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Release()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    lppVideoPlayerServer_->Release();
    lppVideoPlayerServer_ = nullptr;
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::Release(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Release());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetVolume(float volume)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->SetVolume(volume);
}

int32_t LppVideoStreamerServiceStub::SetVolume(MessageParcel &data, MessageParcel &reply)
{
    float volume = data.ReadFloat();
    reply.WriteInt32(SetVolume(volume));
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::StartDecode()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->StartDecode();
}

int32_t LppVideoStreamerServiceStub::StartDecode(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = StartDecode();
    reply.WriteInt32(result);
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::StartRender()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->StartRender();
}

int32_t LppVideoStreamerServiceStub::StartRender(MessageParcel &data, MessageParcel &reply)
{
    int32_t result = StartRender();
    reply.WriteInt32(result);
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetOutputSurface(sptr<Surface> surface)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->SetOutputSurface(surface);
}

int32_t LppVideoStreamerServiceStub::SetOutputSurface(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "Object is nullptr");

    sptr<IBufferProducer> producer = iface_cast<IBufferProducer>(object);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, MSERR_NO_MEMORY, "Producer is nullptr");

    sptr<OHOS::Surface> surface = OHOS::Surface::CreateSurfaceAsProducer(producer);
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_NO_MEMORY, "Surface create failed");

    std::string format = data.ReadString();
    MEDIA_LOGD("Surface format is %{public}s!", format.c_str());
    const std::string surfaceFormat = "SURFACE_FORMAT";
    (void)surface->SetUserData(surfaceFormat, format);

    bool ret = reply.WriteInt32(SetOutputSurface(surface));
    CHECK_AND_RETURN_RET_LOG(ret, MSERR_INVALID_OPERATION, "Reply write failed");
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetSyncAudioStreamer(AudioStreamer *audioStreamer)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->SetSyncAudioStreamer(audioStreamer);
}

int32_t LppVideoStreamerServiceStub::SetSyncAudioStreamer(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "object is nullptr");
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetTargetStartFrame(const int64_t targetPts, const int timeoutMs)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->SetTargetStartFrame(targetPts, timeoutMs);
}

int32_t LppVideoStreamerServiceStub::SetTargetStartFrame(MessageParcel &data, MessageParcel &reply)
{
    int64_t targetPts = data.ReadInt64();
    int timeoutMs = data.ReadInt32();
    int32_t result = SetTargetStartFrame(targetPts, timeoutMs);
    reply.WriteInt32(result);
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetPlaybackSpeed(float speed)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->SetPlaybackSpeed(speed);
}

int32_t LppVideoStreamerServiceStub::SetPlaybackSpeed(MessageParcel &data, MessageParcel &reply)
{
    float speed = data.ReadFloat();
    reply.WriteInt32(SetPlaybackSpeed(speed));
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    CHECK_AND_RETURN_RET_LOG(framePacket != nullptr, MSERR_INVALID_VAL, "framePacket is nullptr");
    return lppVideoPlayerServer_->ReturnFrames(framePacket);
}

int32_t LppVideoStreamerServiceStub::ReturnFrames(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    framePacket_->Clear();
    framePacket_->ReadFromMessageParcel(data);
    reply.WriteInt32(ReturnFrames(framePacket_));
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::RegisterCallback()
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->RegisterCallback();
}

int32_t LppVideoStreamerServiceStub::RegisterCallback(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(RegisterCallback());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetListenerObject(const sptr<IRemoteObject> &object)
{
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "set listener object is nullptr");

    sptr<IStandardLppVideoStreamerListener> listener = iface_cast<IStandardLppVideoStreamerListener>(object);
    CHECK_AND_RETURN_RET_LOG(
        listener != nullptr, MSERR_NO_MEMORY, "failed to convert IStandardLppVideoStreamerListener");

    std::shared_ptr<VideoStreamerCallback> callback = std::make_shared<LppVideoStreamerListenerCallback>(listener);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_NO_MEMORY, "failed to new LppAudioStreamListenerCallback");
    playerCallback_ = callback;
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetListenerObject(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    reply.WriteInt32(SetListenerObject(object));
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetLppVideoStreamerCallback()
{
    MEDIA_LOGD("SetLppVideoStreamerCallback");
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION,
        "lppaudioplayer server is nullptr");
    return lppVideoPlayerServer_->SetLppVideoStreamerCallback(playerCallback_);
}

int32_t LppVideoStreamerServiceStub::SetLppVideoStreamerCallback(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(SetLppVideoStreamerCallback());
    return MSERR_OK;
}

std::string LppVideoStreamerServiceStub::GetStreamerId()
{
    MEDIA_LOGD("GetStreamerId");
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, "", "player server is nullptr");
    return lppVideoPlayerServer_->GetStreamerId();
}

int32_t LppVideoStreamerServiceStub::GetStreamerId(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteString(GetStreamerId());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::SetLppAudioStreamerId(std::string audioStreamId)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->SetLppAudioStreamerId(audioStreamId);
}

int32_t LppVideoStreamerServiceStub::SetLppAudioStreamerId(MessageParcel &data, MessageParcel &reply)
{
    std::string audioStreamId = data.ReadString();
    reply.WriteInt32(SetLppAudioStreamerId(audioStreamId));
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::RenderFirstFrame()
{
    MEDIA_LOGD("RenderFirstFrame");
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->RenderFirstFrame();
}

int32_t LppVideoStreamerServiceStub::RenderFirstFrame(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(RenderFirstFrame());
    return MSERR_OK;
}

int32_t LppVideoStreamerServiceStub::GetLatestPts(int64_t &pts)
{
    MEDIA_LOGI("LppVideoStreamerServiceStub::GetLatestPts");
    CHECK_AND_RETURN_RET_LOG(lppVideoPlayerServer_ != nullptr, MSERR_INVALID_OPERATION, "player server is nullptr");
    return lppVideoPlayerServer_->GetLatestPts(pts);
}

int32_t LppVideoStreamerServiceStub::GetLatestPts(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    int64_t pts = 0;
    int32_t ret = GetLatestPts(pts);
    MEDIA_LOGI("LppVideoStreamerServiceStub::GetLatestPts %{public}d %{public}ld", ret, pts);
    reply.WriteInt32(ret);
    reply.WriteInt64(pts);
    return MSERR_OK;
}
}  // namespace Media
}  // namespace OHOS

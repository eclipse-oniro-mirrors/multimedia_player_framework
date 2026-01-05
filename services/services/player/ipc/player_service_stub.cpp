/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#include "player_service_stub.h"
#include <unistd.h>
#include "player_listener_proxy.h"
#include "media_data_source_proxy.h"
#include "media_server_manager.h"
#include "dolby_passthrough_proxy.h"

#ifdef SUPPORT_AVPLAYER_DRM
#include "media_key_session_service_proxy.h"
#endif
#include "media_log.h"
#include "media_errors.h"
#include "media_parcel.h"
#include "parameter.h"
#include "media_dfx.h"
#include "player_xcollie.h"
#include "av_common.h"
#ifdef SUPPORT_AVSESSION
#include "avsession_background.h"
#endif
#include "media_source_loader_proxy.h"
#include "audio_background_adapter.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "PlayerServiceStub"};
    constexpr uint32_t MAX_MAP_SIZE = 100;
    constexpr size_t MAX_PAYLOAD_TYPES_SIZE = 100;
    constexpr uint32_t MAX_MEDIA_STREAM_LIST_SIZE = 10;
}

namespace OHOS {
namespace Media {
sptr<PlayerServiceStub> PlayerServiceStub::Create()
{
    sptr<PlayerServiceStub> playerStub = new(std::nothrow) PlayerServiceStub();
    CHECK_AND_RETURN_RET_LOG(playerStub != nullptr, nullptr, "failed to new PlayerServiceStub");

    int32_t ret = playerStub->Init();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to player stub init");
    return playerStub;
}

PlayerServiceStub::PlayerServiceStub()
    : taskQue_("PlayerRequest")
{
    (void)taskQue_.Start();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

PlayerServiceStub::~PlayerServiceStub()
{
    (void)CancellationMonitor(appPid_);
    if (playerServer_ != nullptr) {
        auto task = std::make_shared<TaskHandler<void>>([&, this] {
            (void)playerServer_->Release();
            playerServer_ = nullptr;
        });
        (void)taskQue_.EnqueueTask(task);
        (void)task->GetResult();
    }
    (void)taskQue_.Stop();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t PlayerServiceStub::Freeze()
{
    MediaTrace trace("PlayerServiceStub::Freeze");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Stub received Freeze", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    auto task = std::make_shared<TaskHandler<int32_t>>([this] {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Stub freeze in", FAKE_POINTER(this));
        int32_t ret = MSERR_OK;
        CHECK_AND_RETURN_RET_LOG(!isFrozen_, ret, "can not freeze");
        (void)DisableMonitor(appPid_);
        CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr,
            static_cast<int32_t>(MSERR_NO_MEMORY), "player server is nullptr");
        ret = playerServer_->Freeze();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "Freeze failed");
        isFrozen_ = true;
        return ret;
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    return MSERR_OK;
}

int32_t PlayerServiceStub::UnFreeze()
{
    MediaTrace trace("PlayerServiceStub::UnFreeze");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Stub received Unfreeze", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    auto task = std::make_shared<TaskHandler<int32_t>>([this] {
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Stub Unfreeze in", FAKE_POINTER(this));
        int32_t ret = MSERR_OK;
        CHECK_AND_RETURN_RET_LOG(isFrozen_, ret, "can not UnFreeze");
        ret = playerServer_->UnFreeze();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "UnFreeze failed");
        (void)EnableMonitor(appPid_);
        isFrozen_ = false;
        return ret;
    });
    int32_t ret = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "EnqueueTask failed");
    return MSERR_OK;
}

void PlayerServiceStub::SetPlayerFuncs()
{
    FillPlayerFuncPart1();
    FillPlayerFuncPart2();
    FillPlayerFuncPart3();
    (void)RegisterMonitor(appPid_);
}

void PlayerServiceStub::FillPlayerFuncPart1()
{
    playerFuncs_[SET_LISTENER_OBJ] = { "Player::SetListenerObject",
        [this](MessageParcel &data, MessageParcel &reply) { return SetListenerObject(data, reply); } };
    playerFuncs_[SET_SOURCE] = { "Player::SetSource",
        [this](MessageParcel &data, MessageParcel &reply) { return SetSource(data, reply); } };
    playerFuncs_[SET_MEDIA_DATA_SRC_OBJ] = { "Player::SetMediaDataSource",
        [this](MessageParcel &data, MessageParcel &reply) { return SetMediaDataSource(data, reply); } };
    playerFuncs_[SET_FD_SOURCE] = { "Player::SetFdSource",
        [this](MessageParcel &data, MessageParcel &reply) { return SetFdSource(data, reply); } };
    playerFuncs_[PLAY] = { "Player::Play",
        [this](MessageParcel &data, MessageParcel &reply) { return Play(data, reply); } };
    playerFuncs_[PREPARE] = { "Player::Prepare",
        [this](MessageParcel &data, MessageParcel &reply) { return Prepare(data, reply); } };
    playerFuncs_[SET_RENDER_FIRST_FRAME] = { "Player::SetRenderFirstFrame",
        [this](MessageParcel &data, MessageParcel &reply) { return SetRenderFirstFrame(data, reply); } };
    playerFuncs_[PREPAREASYNC] = { "Player::PrepareAsync",
        [this](MessageParcel &data, MessageParcel &reply) { return PrepareAsync(data, reply); } };
    playerFuncs_[PAUSE] = { "Player::Pause",
        [this](MessageParcel &data, MessageParcel &reply) { return Pause(data, reply); } };
    playerFuncs_[STOP] = { "Player::Stop",
        [this](MessageParcel &data, MessageParcel &reply) { return Stop(data, reply); } };
    playerFuncs_[RESET] = { "Player::Reset",
        [this](MessageParcel &data, MessageParcel &reply) { return Reset(data, reply); } };
    playerFuncs_[RELEASE] = { "Player::Release",
        [this](MessageParcel &data, MessageParcel &reply) { return Release(data, reply); } };
    playerFuncs_[SET_VOLUME] = { "Player::SetVolume",
        [this](MessageParcel &data, MessageParcel &reply) { return SetVolume(data, reply); } };
    playerFuncs_[SEEK] = { "Player::Seek",
        [this](MessageParcel &data, MessageParcel &reply) { return Seek(data, reply); } };
    playerFuncs_[GET_CURRENT_TIME] = { "Player::GetCurrentTime",
        [this](MessageParcel &data, MessageParcel &reply) { return GetCurrentTime(data, reply); } };
    playerFuncs_[GET_DURATION] = { "Player::GetDuration",
        [this](MessageParcel &data, MessageParcel &reply) { return GetDuration(data, reply); } };
    playerFuncs_[SET_PLAYERBACK_SPEED] = { "Player::SetPlaybackSpeed",
        [this](MessageParcel &data, MessageParcel &reply) { return SetPlaybackSpeed(data, reply); } };
    playerFuncs_[GET_PLAYERBACK_SPEED] = { "Player::GetPlaybackSpeed",
        [this](MessageParcel &data, MessageParcel &reply) { return GetPlaybackSpeed(data, reply); } };
    playerFuncs_[SET_MEDIA_SOURCE] = { "Player::SetMediaSource",
        [this](MessageParcel &data, MessageParcel &reply) { return SetMediaSource(data, reply); } };
#ifdef SUPPORT_VIDEO
    playerFuncs_[SET_VIDEO_SURFACE] = { "Player::SetVideoSurface",
        [this](MessageParcel &data, MessageParcel &reply) { return SetVideoSurface(data, reply); } };
#endif
    playerFuncs_[IS_PLAYING] = { "Player::IsPlaying",
        [this](MessageParcel &data, MessageParcel &reply) { return IsPlaying(data, reply); } };
    playerFuncs_[IS_LOOPING] = { "Player::IsLooping",
        [this](MessageParcel &data, MessageParcel &reply) { return IsLooping(data, reply); } };
    playerFuncs_[SET_LOOPING] = { "Player::SetLooping",
        [this](MessageParcel &data, MessageParcel &reply) { return SetLooping(data, reply); } };
}

void PlayerServiceStub::FillPlayerFuncPart2()
{
    playerFuncs_[ADD_SUB_SOURCE] = { "Player::AddSubSource",
        [this](MessageParcel &data, MessageParcel &reply) { return AddSubSource(data, reply); } };
    playerFuncs_[ADD_SUB_FD_SOURCE] = { "Player::AddSubFdSource",
        [this](MessageParcel &data, MessageParcel &reply) { return AddSubFdSource(data, reply); } };
    playerFuncs_[SET_RENDERER_DESC] = { "Player::SetParameter",
        [this](MessageParcel &data, MessageParcel &reply) { return SetParameter(data, reply); } };
    playerFuncs_[DESTROY] = { "Player::DestroyStub",
        [this](MessageParcel &data, MessageParcel &reply) { return DestroyStub(data, reply); } };
    playerFuncs_[SET_CALLBACK] = { "Player::SetPlayerCallback",
        [this](MessageParcel &data, MessageParcel &reply) { return SetPlayerCallback(data, reply); } };
    playerFuncs_[GET_VIDEO_TRACK_INFO] = { "Player::GetVideoTrackInfo",
        [this](MessageParcel &data, MessageParcel &reply) { return GetVideoTrackInfo(data, reply); } };
    playerFuncs_[GET_PLAYBACK_INFO] = { "Player::GetPlaybackInfo",
        [this](MessageParcel &data, MessageParcel &reply) { return GetPlaybackInfo(data, reply); } };
    playerFuncs_[GET_PLAYBACK_STATISTIC_METRICS] = { "Player::GetPlaybackStatisticMetrics",
        [this](MessageParcel &data, MessageParcel &reply) { return GetPlaybackStatisticMetrics(data, reply); } };
    playerFuncs_[GET_AUDIO_TRACK_INFO] = { "Player::GetAudioTrackInfo",
        [this](MessageParcel &data, MessageParcel &reply) { return GetAudioTrackInfo(data, reply); } };
    playerFuncs_[GET_SUBTITLE_TRACK_INFO] = { "Player::GetSubtitleTrackInfo",
        [this](MessageParcel &data, MessageParcel &reply) { return GetSubtitleTrackInfo(data, reply); } };
    playerFuncs_[GET_VIDEO_WIDTH] = { "Player::GetVideoWidth",
        [this](MessageParcel &data, MessageParcel &reply) { return GetVideoWidth(data, reply); } };
    playerFuncs_[GET_VIDEO_HEIGHT] = { "Player::GetVideoHeight",
        [this](MessageParcel &data, MessageParcel &reply) { return GetVideoHeight(data, reply); } };
    playerFuncs_[SELECT_BIT_RATE] = { "Player::SelectBitRate",
        [this](MessageParcel &data, MessageParcel &reply) { return SelectBitRate(data, reply); } };
    playerFuncs_[SELECT_TRACK] = { "Player::SelectTrack",
        [this](MessageParcel &data, MessageParcel &reply) { return SelectTrack(data, reply); } };
    playerFuncs_[DESELECT_TRACK] = { "Player::DeselectTrack",
        [this](MessageParcel &data, MessageParcel &reply) { return DeselectTrack(data, reply); } };
    playerFuncs_[GET_CURRENT_TRACK] = { "Player::GetCurrentTrack",
        [this](MessageParcel &data, MessageParcel &reply) { return GetCurrentTrack(data, reply); } };
    playerFuncs_[SET_DECRYPT_CONFIG] = { "Player::SetDecryptConfig",
        [this](MessageParcel &data, MessageParcel &reply) { return SetDecryptConfig(data, reply); } };
    playerFuncs_[SET_PLAY_RANGE] = { "Player::SetPlayRange",
        [this](MessageParcel &data, MessageParcel &reply) { return SetPlayRange(data, reply); } };
    playerFuncs_[SET_PLAY_RANGE_WITH_MODE] = { "SetPlayRangeWithMode",
        [this](MessageParcel &data, MessageParcel &reply) { return SetPlayRangeWithMode(data, reply); } };
    playerFuncs_[SET_PLAYBACK_STRATEGY] = { "SetPlaybackStrategy",
        [this](MessageParcel &data, MessageParcel &reply) { return SetPlaybackStrategy(data, reply); } };
    playerFuncs_[SET_MEDIA_MUTED] = { "SetMediaMuted",
        [this](MessageParcel &data, MessageParcel &reply) { return SetMediaMuted(data, reply); } };
    playerFuncs_[SET_MAX_AMPLITUDE_CB_STATUS] = { "Player::SetMaxAmplitudeCbStatus",
        [this](MessageParcel &data, MessageParcel &reply) { return SetMaxAmplitudeCbStatus(data, reply); } };
    playerFuncs_[SET_DEVICE_CHANGE_CB_STATUS] = { "Player::SetDeviceChangeCbStatus",
        [this](MessageParcel &data, MessageParcel &reply) { return SetDeviceChangeCbStatus(data, reply); } };
    playerFuncs_[GET_API_VERSION] = { "GetApiVersion",
        [this](MessageParcel &data, MessageParcel &reply) { return GetApiVersion(data, reply); } };
    playerFuncs_[IS_SEEK_CONTINUOUS_SUPPORTED] = { "IsSeekContinuousSupported",
        [this](MessageParcel &data, MessageParcel &reply) { return IsSeekContinuousSupported(data, reply); } };
}

void PlayerServiceStub::FillPlayerFuncPart3()
{
    playerFuncs_[GET_PLAY_BACK_POSITION] = { "Player::GetPlaybackPosition",
        [this](MessageParcel &data, MessageParcel &reply) { return GetPlaybackPosition(data, reply); } };
    playerFuncs_[SET_SEI_MESSAGE_CB_STATUS] = { "Player::SetSeiMessageCbStatus",
        [this](MessageParcel &data, MessageParcel &reply) { return SetSeiMessageCbStatus(data, reply); } };
    playerFuncs_[SET_SOURCE_LOADER] = { "SetSourceLoader",
        [this](MessageParcel &data, MessageParcel &reply) { return SetSourceLoader(data, reply); } };
    playerFuncs_[SET_SUPER_RESOLUTION] = { "Player::SetSuperResolution",
        [this](MessageParcel &data, MessageParcel &reply) { return SetSuperResolution(data, reply); } };
    playerFuncs_[SET_VIDEO_WINDOW_SIZE] = { "Player::SetVideoWindowSize",
        [this](MessageParcel &data, MessageParcel &reply) { return SetVideoWindowSize(data, reply); } };
    playerFuncs_[SET_VOLUME_MODE] = { "Player::SetVolumeMode",
        [this](MessageParcel &data, MessageParcel &reply) { return SetVolumeMode(data, reply); } };
    playerFuncs_[SET_START_FRAME_RATE_OPT_ENABLED] = { "Player::SetStartFrameRateOptEnabled",
        [this](MessageParcel &data, MessageParcel &reply) { return SetStartFrameRateOptEnabled(data, reply); } };
    playerFuncs_[SET_REOPEN_FD] = { "Player::SetReopenFd",
        [this](MessageParcel &data, MessageParcel &reply) { return SetReopenFd(data, reply); } };
    playerFuncs_[ENABLE_CAMERA_POSTPROCESSING] = { "Player::EnableCameraPostprocessing",
        [this](MessageParcel &data, MessageParcel &reply) { return EnableCameraPostprocessing(data, reply); } };
    playerFuncs_[SET_PLAYERBACK_RATE] = { "Player::SetPlaybackRate",
        [this](MessageParcel &data, MessageParcel &reply) { return SetPlaybackRate(data, reply); } };
    playerFuncs_[GET_PLAYERBACK_RATE] = { "Player::GetPlaybackRate",
        [this](MessageParcel &data, MessageParcel &reply) { return GetPlaybackRate(data, reply); } };
    playerFuncs_[ENABLE_REPORT_MEDIA_PROGRESS] = { "Player::EnableReportMediaProgress",
        [this](MessageParcel &data, MessageParcel &reply) { return EnableReportMediaProgress(data, reply); } };
    playerFuncs_[ENABLE_REPORT_AUDIO_INTERRUPT] = { "Player::EnableReportAudioInterrupt",
        [this](MessageParcel &data, MessageParcel &reply) { return EnableReportAudioInterrupt(data, reply); } };
    playerFuncs_[SET_PLAYER_PRODUCER] = { "Player::SetPlayerProducer",
        [this](MessageParcel &data, MessageParcel &reply) { return SetPlayerProducer(data, reply); } };
    playerFuncs_[FORCE_LOAD_VIDEO] = { "Player::ForceLoadVideo",
        [this](MessageParcel &data, MessageParcel &reply) { return ForceLoadVideo(data, reply); } };
    playerFuncs_[SET_LOUDNESSGAIN] = { "Player::SetLoudnessGain",
        [this](MessageParcel &data, MessageParcel &reply) { return SetLoudnessGain(data, reply); } };
    playerFuncs_[SET_CAMERA_POST_POSTPROCESSING] = { "Player::SetCameraPostprocessing",
        [this](MessageParcel &data, MessageParcel &reply) { return SetCameraPostprocessing(data, reply); } };
    playerFuncs_[GET_GLOBAL_INFO] = { "Player::GetGlobalInfo",
        [this](MessageParcel &data, MessageParcel &reply) { return GetGlobalInfo(data, reply); } };
    playerFuncs_[GET_MEDIA_DESCRIPTION] = { "Player::GET_MEDIA_DESCRIPTION",
        [this](MessageParcel &data, MessageParcel &reply) { return GetMediaDescription(data, reply); } };
    playerFuncs_[GET_TRACK_DESCRIPTION] = { "Player::GET_TRACK_DESCRIPTION",
        [this](MessageParcel &data, MessageParcel &reply) { return GetTrackDescription(data, reply); } };
    playerFuncs_[GET_CURRENT_PRESENTATION_TIMESTAMP] = { "Player::GetCurrentPresentationTimestamp",
        [this](MessageParcel &data, MessageParcel &reply) { return GetCurrentPresentationTimestamp(data, reply); } };
    playerFuncs_[REGISTER_DEVICE_CAPABILITY] = { "Player::RegisterDeviceCapability",
        [this](MessageParcel &data, MessageParcel &reply) { return RegisterDeviceCapability(data, reply); } };
}

int32_t PlayerServiceStub::Init()
{
    if (playerServer_ == nullptr) {
        playerServer_ = PlayerServer::Create();
    }
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "failed to create PlayerServer");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create 0x%{public}06" PRIXPTR,
        FAKE_POINTER(this), FAKE_POINTER(playerServer_.get()));
    appUid_ = IPCSkeleton::GetCallingUid();
    appPid_ = IPCSkeleton::GetCallingPid();
    SetPlayerFuncs();
    return MSERR_OK;
}

int32_t PlayerServiceStub::DestroyStub()
{
    MediaTrace trace("PlayerServiceStub::DestroyStub");
    playerCallback_ = nullptr;
    if (playerServer_ != nullptr) {
        (void)playerServer_->Release();
        playerServer_ = nullptr;
    }

    MediaServerManager::GetInstance().DestroyStubObject(MediaServerManager::PLAYER, AsObject());
    return MSERR_OK;
}

int PlayerServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    MediaTrace trace("PlayerServiceStub::OnRemoteRequest");
    auto remoteDescriptor = data.ReadInterfaceToken();
    CHECK_AND_RETURN_RET_LOG(PlayerServiceStub::GetDescriptor() == remoteDescriptor,
        MSERR_INVALID_OPERATION, "Invalid descriptor");

    auto itFunc = playerFuncs_.find(code);
    if (itFunc != playerFuncs_.end()) {
        auto memberFunc = itFunc->second.second;
        auto funcName = itFunc->second.first;
        if (funcName.compare("Player::SetVolume") == 0 || funcName.compare("Player::GetCurrentTime") == 0) {
            MEDIA_LOGD("0x%{public}06" PRIXPTR " Stub: OnRemoteRequest task: %{public}s is received",
                FAKE_POINTER(this), funcName.c_str());
        } else {
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Stub: OnRemoteRequest task: %{public}s is received",
                FAKE_POINTER(this), funcName.c_str());
        }
        if (memberFunc != nullptr) {
            auto task = std::make_shared<TaskHandler<int>>([&, this] {
                (void)IpcRecovery(false);
                auto res = CheckandDoUnFreeze();
                CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, res, "UnFreeze failed");
                int32_t ret = -1;
                ret = memberFunc(data, reply);
                return ret;
            });
            (void)taskQue_.EnqueueTask(task);
            auto result = task->GetResult();
            CHECK_AND_RETURN_RET_LOG(result.HasResult(), MSERR_INVALID_OPERATION,
                "failed to OnRemoteRequest code: %{public}u", code);
            return result.Value();
        }
    }
    MEDIA_LOGW("PlayerServiceStub: no member func supporting, applying default process");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t PlayerServiceStub::CheckandDoUnFreeze()
{
    CHECK_AND_RETURN_RET_NOLOG(isFrozen_, MSERR_OK);
    MEDIA_LOGE("UnFreeze Later");
    auto ret = playerServer_->UnFreeze();
    CHECK_AND_RETURN_RET_NOLOG(ret == MSERR_OK, ret);
    (void)EnableMonitor(appPid_);
    isFrozen_ = false;
    return ret;
}

int32_t PlayerServiceStub::SetListenerObject(const sptr<IRemoteObject> &object)
{
    MediaTrace trace("PlayerServiceStub::SetListenerObject");
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "set listener object is nullptr");

    sptr<IStandardPlayerListener> listener = iface_cast<IStandardPlayerListener>(object);
    CHECK_AND_RETURN_RET_LOG(listener != nullptr, MSERR_NO_MEMORY, "failed to convert IStandardPlayerListener");

    std::shared_ptr<PlayerCallback> callback = std::make_shared<PlayerListenerCallback>(listener);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_NO_MEMORY, "failed to new PlayerListenerCallback");

    playerCallback_ = callback;
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetPlayerProducer(const PlayerProducer producer)
{
    MediaTrace trace("PlayerServiceStub::SetPlayerProducer");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetPlayerProducer(producer);
}

int32_t PlayerServiceStub::SetSource(const std::string &url)
{
    MediaTrace trace("PlayerServiceStub::SetSource(url)");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetSource(url);
}

int32_t PlayerServiceStub::SetSource(const sptr<IRemoteObject> &object)
{
    MediaTrace trace("PlayerServiceStub::SetSource(datasource)");
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "set mediadatasrc object is nullptr");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");

    sptr<IStandardMediaDataSource> proxy = iface_cast<IStandardMediaDataSource>(object);
    CHECK_AND_RETURN_RET_LOG(proxy != nullptr, MSERR_NO_MEMORY, "failed to convert MediaDataSourceProxy");

    std::shared_ptr<IMediaDataSource> mediaDataSrc = std::make_shared<MediaDataCallback>(proxy);
    CHECK_AND_RETURN_RET_LOG(mediaDataSrc != nullptr, MSERR_NO_MEMORY, "failed to new PlayerListenerCallback");

    return playerServer_->SetSource(mediaDataSrc);
}

int32_t PlayerServiceStub::SetSourceLoader(const sptr<IRemoteObject> &object)
{
    MediaTrace trace("PlayerServiceStub::SetSourceLoader(sourceLoader)");
    MEDIA_LOGI("SetSourceLoader in");
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "set sourceLoader object is nullptr");
 
    sptr<IStandardMediaSourceLoader> proxy = iface_cast<IStandardMediaSourceLoader>(object);
    CHECK_AND_RETURN_RET_LOG(proxy != nullptr, MSERR_NO_MEMORY, "failed to convert MediaSourceLoaderProxy");
 
    sourceLoader_ = std::make_shared<MediaSourceLoaderCallback>(proxy);
    CHECK_AND_RETURN_RET_LOG(sourceLoader_ != nullptr, MSERR_NO_MEMORY, "failed to new MediaSourceLoaderCallback");
 
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetSource(int32_t fd, int64_t offset, int64_t size)
{
    MediaTrace trace("PlayerServiceStub::SetSource(fd)");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetSource(fd, offset, size);
}

int32_t PlayerServiceStub::AddSubSource(const std::string &url)
{
    MediaTrace trace("PlayerServiceStub::AddSubSource(url)");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->AddSubSource(url);
}

int32_t PlayerServiceStub::AddSubSource(int32_t fd, int64_t offset, int64_t size)
{
    MediaTrace trace("PlayerServiceStub::AddSubSource(fd)");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->AddSubSource(fd, offset, size);
}

int32_t PlayerServiceStub::Play()
{
    MediaTrace trace("PlayerServiceStub::Play");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
#ifdef SUPPORT_AVSESSION
    AVsessionBackground::Instance().AddListener(playerServer_, appUid_);
#endif
    AudioBackgroundAdapter::Instance().AddListener(playerServer_, appUid_);
    return playerServer_->Play();
}

int32_t PlayerServiceStub::Prepare()
{
    MediaTrace trace("PlayerServiceStub::Prepare");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->Prepare();
}

int32_t PlayerServiceStub::SetRenderFirstFrame(bool display)
{
    MediaTrace trace("Stub::SetRenderFirstFrame");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetRenderFirstFrame(display);
}

int32_t PlayerServiceStub::SetPlayRange(int64_t start, int64_t end)
{
    MediaTrace trace("Stub::SetPlayRange");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetPlayRange(start, end);
}

int32_t PlayerServiceStub::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    MediaTrace trace("Stub::SetPlayRangeWithMode");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetPlayRangeWithMode(start, end, mode);
}

int32_t PlayerServiceStub::PrepareAsync()
{
    MediaTrace trace("PlayerServiceStub::PrepareAsync");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->PrepareAsync();
}

int32_t PlayerServiceStub::Pause()
{
    MediaTrace trace("PlayerServiceStub::Pause");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->Pause();
}

int32_t PlayerServiceStub::Stop()
{
    MediaTrace trace("PlayerServiceStub::Stop");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->Stop();
}

int32_t PlayerServiceStub::Reset()
{
    MediaTrace trace("PlayerServiceStub::Reset");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->Reset();
}

int32_t PlayerServiceStub::Release()
{
    MediaTrace trace("PlayerServiceStub::Release");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    int32_t ret = playerServer_->Release();
    playerCallback_ = nullptr;
    return ret;
}

int32_t PlayerServiceStub::SetVolume(float leftVolume, float rightVolume)
{
    MediaTrace trace("PlayerServiceStub::SetVolume");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetVolume(leftVolume, rightVolume);
}

int32_t PlayerServiceStub::SetVolumeMode(int32_t mode)
{
    MediaTrace trace("PlayerServiceStub::SetVolumeMode");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetVolumeMode(mode);
}

int32_t PlayerServiceStub::SetStartFrameRateOptEnabled(bool enabled)
{
    MediaTrace trace("PlayerServiceStub::SetStartFrameRateOptEnabled");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetStartFrameRateOptEnabled(enabled);
}

int32_t PlayerServiceStub::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    MediaTrace trace("PlayerServiceStub::Seek");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->Seek(mSeconds, mode);
}

int32_t PlayerServiceStub::GetCurrentTime(int32_t &currentTime)
{
    MediaTrace trace("PlayerServiceStub::GetCurrentTime");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetCurrentTime(currentTime);
}

int32_t PlayerServiceStub::GetPlaybackPosition(int32_t &playbackPosition)
{
    MediaTrace trace("PlayerServiceStub::GetPlaybackPosition");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetPlaybackPosition(playbackPosition);
}

int32_t PlayerServiceStub::GetCurrentPresentationTimestamp(int64_t &currentPresentation)
{
    MediaTrace trace("PlayerServiceStub::GetCurrentPresentationTimestamp");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetCurrentPresentationTimestamp(currentPresentation);
}

int32_t PlayerServiceStub::GetVideoTrackInfo(std::vector<Format> &videoTrack)
{
    MediaTrace trace("PlayerServiceStub::GetVideoTrackInfo");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetVideoTrackInfo(videoTrack);
}

int32_t PlayerServiceStub::GetPlaybackInfo(Format &playbackInfo)
{
    MediaTrace trace("PlayerServiceStub::GetPlaybackInfo");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetPlaybackInfo(playbackInfo);
}

int32_t PlayerServiceStub::GetPlaybackStatisticMetrics(Format &playbackStatisticMetrics)
{
    MediaTrace trace("PlayerServiceStub::GetPlaybackStatisticMetrics");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    MEDIA_LOGI("GetPlaybackStatisticMetrics(core) request");
    return playerServer_->GetPlaybackStatisticMetrics(playbackStatisticMetrics);
}

int32_t PlayerServiceStub::GetAudioTrackInfo(std::vector<Format> &audioTrack)
{
    MediaTrace trace("PlayerServiceStub::GetAudioTrackInfo");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetAudioTrackInfo(audioTrack);
}

int32_t PlayerServiceStub::GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack)
{
    MediaTrace trace("PlayerServiceStub::GetSubtitleTrackInfo");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetSubtitleTrackInfo(subtitleTrack);
}

int32_t PlayerServiceStub::GetVideoWidth()
{
    MediaTrace trace("PlayerServiceStub::GetVideoWidth");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetVideoWidth();
}

int32_t PlayerServiceStub::GetVideoHeight()
{
    MediaTrace trace("PlayerServiceStub::GetVideoHeight");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetVideoHeight();
}

int32_t PlayerServiceStub::GetDuration(int32_t &duration)
{
    MediaTrace trace("PlayerServiceStub::GetDuration");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetDuration(duration);
}

int32_t PlayerServiceStub::GetApiVersion(int32_t &apiVersion)
{
    MediaTrace trace("PlayerServiceStub::GetApiVersion");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetApiVersion(apiVersion);
}

int32_t PlayerServiceStub::SetPlaybackSpeed(PlaybackRateMode mode)
{
    MediaTrace trace("PlayerServiceStub::SetPlaybackSpeed");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetPlaybackSpeed(mode);
}

int32_t PlayerServiceStub::SetPlaybackRate(float rate)
{
    MediaTrace trace("PlayerServiceStub::SetPlaybackRate");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetPlaybackRate(rate);
}

int32_t PlayerServiceStub::SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy)
{
    CHECK_AND_RETURN_RET_LOG(mediaSource != nullptr, MSERR_INVALID_VAL, "mediaSource is nullptr");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetMediaSource(mediaSource, strategy);
}

int32_t PlayerServiceStub::GetPlaybackSpeed(PlaybackRateMode &mode)
{
    MediaTrace trace("PlayerServiceStub::GetPlaybackSpeed");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetPlaybackSpeed(mode);
}

int32_t PlayerServiceStub::GetPlaybackRate(float &rate)
{
    MediaTrace trace("PlayerServiceStub::GetPlaybackRate");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetPlaybackRate(rate);
}

int32_t PlayerServiceStub::SelectBitRate(uint32_t bitRate)
{
    MediaTrace trace("PlayerServiceStub::SelectBitRate");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SelectBitRate(bitRate);
}

#ifdef SUPPORT_VIDEO
int32_t PlayerServiceStub::SetVideoSurface(sptr<Surface> surface)
{
    MediaTrace trace("PlayerServiceStub::SetVideoSurface");
    MEDIA_LOGD("SetVideoSurface");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetVideoSurface(surface);
}
#endif

int32_t PlayerServiceStub::SetDecryptConfig(const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy,
    bool svp)
{
#ifdef SUPPORT_AVPLAYER_DRM
    MediaTrace trace("PlayerServiceStub::SetDecryptConfig");
    MEDIA_LOGI("PlayerServiceStub SetDecryptConfig");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetDecryptConfig(keySessionProxy, svp);
#else
    (void)keySessionProxy;
    (void)svp;
    return 0;
#endif
}

bool PlayerServiceStub::IsPlaying()
{
    MediaTrace trace("PlayerServiceStub::IsPlaying");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, false, "player server is nullptr");
    return playerServer_->IsPlaying();
}

bool PlayerServiceStub::IsLooping()
{
    MediaTrace trace("PlayerServiceStub::IsLooping");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, false, "player server is nullptr");
    return playerServer_->IsLooping();
}

int32_t PlayerServiceStub::SetLooping(bool loop)
{
    MediaTrace trace("PlayerServiceStub::SetLooping");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetLooping(loop);
}

int32_t PlayerServiceStub::SetParameter(const Format &param)
{
    MediaTrace trace("PlayerServiceStub::SetParameter");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetParameter(param);
}

bool PlayerServiceStub::IsSeekContinuousSupported()
{
    MediaTrace trace("PlayerServiceStub::IsSeekContinuousSupported");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, false, "player server is nullptr");
    return playerServer_->IsSeekContinuousSupported();
}

int32_t PlayerServiceStub::SetPlayerCallback()
{
    MediaTrace trace("PlayerServiceStub::SetPlayerCallback");
    MEDIA_LOGD("SetPlayerCallback");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetPlayerCallback(playerCallback_);
}

int32_t PlayerServiceStub::DumpInfo(int32_t fd)
{
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return std::static_pointer_cast<PlayerServer>(playerServer_)->DumpInfo(fd);
}

int32_t PlayerServiceStub::DoIpcAbnormality()
{
    MEDIA_LOGI("Enter DoIpcAbnormality.");
    auto task = std::make_shared<TaskHandler<int>>([&, this] {
        MEDIA_LOGI("DoIpcAbnormality.");
        CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, static_cast<int>(MSERR_NO_MEMORY),
            "player server is nullptr");
        CHECK_AND_RETURN_RET_LOG(IsPlaying(), static_cast<int>(MSERR_INVALID_OPERATION), "Not in playback state");
        auto playerServer = std::static_pointer_cast<PlayerServer>(playerServer_);
        int32_t ret = playerServer->BackGroundChangeState(PlayerStates::PLAYER_PAUSED, false);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "DoIpcAbnormality End.");
        SetIpcAlarmedFlag();
        MEDIA_LOGI("DoIpcAbnormality End.");
        return ret;
    });
    (void)taskQue_.EnqueueTask(task);
    return MSERR_OK;
}

int32_t PlayerServiceStub::DoIpcRecovery(bool fromMonitor)
{
    MEDIA_LOGI("Enter DoIpcRecovery %{public}d.", fromMonitor);
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    if (fromMonitor) {
        auto task = std::make_shared<TaskHandler<int>>([&, this] {
            MEDIA_LOGI("DoIpcRecovery.");
            auto playerServer = std::static_pointer_cast<PlayerServer>(playerServer_);
            int32_t ret = playerServer->BackGroundChangeState(PlayerStates::PLAYER_STARTED, false);
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK || ret == MSERR_INVALID_OPERATION, ret, "Failed to ChangeState");
            UnSetIpcAlarmedFlag();
            MEDIA_LOGI("DoIpcRecovery End.");
            return ret;
        });
        (void)taskQue_.EnqueueTask(task);
    } else {
        auto playerServer = std::static_pointer_cast<PlayerServer>(playerServer_);
        int32_t ret = playerServer->BackGroundChangeState(PlayerStates::PLAYER_STARTED, false);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK || ret == MSERR_INVALID_OPERATION, ret, "Failed to ChangeState");
        UnSetIpcAlarmedFlag();
    }
    return MSERR_OK;
}

int32_t PlayerServiceStub::SelectTrack(int32_t index, PlayerSwitchMode mode)
{
    MediaTrace trace("PlayerServiceStub::SelectTrack");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SelectTrack(index, mode);
}

int32_t PlayerServiceStub::DeselectTrack(int32_t index)
{
    MediaTrace trace("PlayerServiceStub::DeselectTrack");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->DeselectTrack(index);
}

int32_t PlayerServiceStub::GetCurrentTrack(int32_t trackType, int32_t &index)
{
    MediaTrace trace("PlayerServiceStub::GetCurrentTrack");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetCurrentTrack(trackType, index);
}

uint32_t PlayerServiceStub::GetMemoryUsage()
{
    MediaTrace trace("PlayerServiceStub::GetMemoryUsage");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, 0, "player server is nullptr");
    return playerServer_->GetMemoryUsage();
}

int32_t PlayerServiceStub::SetReopenFd(int32_t fd)
{
    MediaTrace trace("PlayerServiceStub::SetReopenFd");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetReopenFd(fd);
}

int32_t PlayerServiceStub::SetListenerObject(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    reply.WriteInt32(SetListenerObject(object));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetPlayerProducer(MessageParcel &data, MessageParcel &reply)
{
    int32_t producer = data.ReadInt32();
    reply.WriteInt32(SetPlayerProducer(static_cast<PlayerProducer>(producer)));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetSource(MessageParcel &data, MessageParcel &reply)
{
    std::string url = data.ReadString();
    reply.WriteInt32(SetSource(url));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetSourceLoader(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    reply.WriteInt32(SetSourceLoader(object));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetMediaDataSource(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    reply.WriteInt32(SetSource(object));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetFdSource(MessageParcel &data, MessageParcel &reply)
{
    int32_t fd = data.ReadFileDescriptor();
    int64_t offset = data.ReadInt64();
    int64_t size = data.ReadInt64();
    reply.WriteInt32(SetSource(fd, offset, size));
    (void)::close(fd);
    return MSERR_OK;
}

int32_t PlayerServiceStub::AddSubSource(MessageParcel &data, MessageParcel &reply)
{
    std::string url = data.ReadString();
    reply.WriteInt32(AddSubSource(url));
    return MSERR_OK;
}

int32_t PlayerServiceStub::AddSubFdSource(MessageParcel &data, MessageParcel &reply)
{
    int32_t fd = data.ReadFileDescriptor();
    int64_t offset = data.ReadInt64();
    int64_t size = data.ReadInt64();
    reply.WriteInt32(AddSubSource(fd, offset, size));
    (void)::close(fd);
    return MSERR_OK;
}

int32_t PlayerServiceStub::Play(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Play());
    return MSERR_OK;
}

int32_t PlayerServiceStub::Prepare(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Prepare());
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetRenderFirstFrame(MessageParcel &data, MessageParcel &reply)
{
    bool display = data.ReadBool();
    reply.WriteInt32(SetRenderFirstFrame(display));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetPlayRange(MessageParcel &data, MessageParcel &reply)
{
    int64_t start = data.ReadInt64();
    int64_t end = data.ReadInt64();
    reply.WriteInt32(SetPlayRange(start, end));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetPlayRangeWithMode(MessageParcel &data, MessageParcel &reply)
{
    int64_t start = data.ReadInt64();
    int64_t end = data.ReadInt64();
    int32_t mode = data.ReadInt32();
    reply.WriteInt32(SetPlayRangeWithMode(start, end, static_cast<PlayerSeekMode>(mode)));
    return MSERR_OK;
}

int32_t PlayerServiceStub::PrepareAsync(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(PrepareAsync());
    return MSERR_OK;
}

int32_t PlayerServiceStub::Pause(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Pause());
    return MSERR_OK;
}

int32_t PlayerServiceStub::Stop(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Stop());
    return MSERR_OK;
}

int32_t PlayerServiceStub::Reset(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Reset());
    return MSERR_OK;
}

int32_t PlayerServiceStub::Release(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(Release());
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetVolumeMode(MessageParcel &data, MessageParcel &reply)
{
    int32_t mode = data.ReadInt32();
    reply.WriteInt32(SetVolumeMode(mode));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetVolume(MessageParcel &data, MessageParcel &reply)
{
    float leftVolume = data.ReadFloat();
    float rightVolume = data.ReadFloat();
    reply.WriteInt32(SetVolume(leftVolume, rightVolume));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetStartFrameRateOptEnabled(MessageParcel &data, MessageParcel &reply)
{
    bool enabled = data.ReadBool();
    reply.WriteInt32(SetStartFrameRateOptEnabled(enabled));
    return MSERR_OK;
}

int32_t PlayerServiceStub::Seek(MessageParcel &data, MessageParcel &reply)
{
    int32_t mSeconds = data.ReadInt32();
    int32_t mode = data.ReadInt32();
    reply.WriteInt32(Seek(mSeconds, static_cast<PlayerSeekMode>(mode)));
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetCurrentTime(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    int32_t currentTime = -1;
    int32_t ret = GetCurrentTime(currentTime);
    reply.WriteInt32(currentTime);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetCurrentPresentationTimestamp(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    int64_t currentPresentation = 0;
    int32_t ret = GetCurrentPresentationTimestamp(currentPresentation);
    reply.WriteInt64(currentPresentation);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetPlaybackPosition(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    int32_t playbackPosition = 0;
    int32_t ret = GetPlaybackPosition(playbackPosition);
    reply.WriteInt32(playbackPosition);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetVideoTrackInfo(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    std::vector<Format> videoTrack;
    int32_t ret = GetVideoTrackInfo(videoTrack);
    reply.WriteInt32(static_cast<int32_t>(videoTrack.size()));
    for (auto iter = videoTrack.begin(); iter != videoTrack.end(); iter++) {
        (void)MediaParcel::Marshalling(reply, *iter);
    }
    reply.WriteInt32(ret);

    return MSERR_OK;
}

int32_t PlayerServiceStub::GetPlaybackInfo(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    Format playbackInfo;
    int32_t ret = GetPlaybackInfo(playbackInfo);
    (void)MediaParcel::Marshalling(reply, playbackInfo);
    reply.WriteInt32(ret);

    return MSERR_OK;
}

int32_t PlayerServiceStub::GetPlaybackStatisticMetrics(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    Format playbackMetrics;
    int32_t ret = GetPlaybackStatisticMetrics(playbackMetrics);
    (void)MediaParcel::Marshalling(reply, playbackMetrics);
    reply.WriteInt32(ret);

    return MSERR_OK;
}

int32_t PlayerServiceStub::GetAudioTrackInfo(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    std::vector<Format> audioTrack;
    int32_t ret = GetAudioTrackInfo(audioTrack);
    reply.WriteInt32(static_cast<int32_t>(audioTrack.size()));
    for (auto iter = audioTrack.begin(); iter != audioTrack.end(); iter++) {
        (void)MediaParcel::Marshalling(reply, *iter);
    }
    reply.WriteInt32(ret);

    return MSERR_OK;
}

int32_t PlayerServiceStub::GetSubtitleTrackInfo(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    std::vector<Format> subtitleTrack;
    int32_t ret = GetSubtitleTrackInfo(subtitleTrack);
    reply.WriteInt32(static_cast<int32_t>(subtitleTrack.size()));
    for (auto iter = subtitleTrack.begin(); iter != subtitleTrack.end(); iter++) {
        (void)MediaParcel::Marshalling(reply, *iter);
    }
    reply.WriteInt32(ret);

    return MSERR_OK;
}

int32_t PlayerServiceStub::GetVideoWidth(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    int32_t witdh = GetVideoWidth();
    reply.WriteInt32(witdh);

    return MSERR_OK;
}

int32_t PlayerServiceStub::GetVideoHeight(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    int32_t height = GetVideoHeight();
    reply.WriteInt32(height);

    return MSERR_OK;
}

int32_t PlayerServiceStub::GetDuration(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    int32_t duration = -1;
    int32_t ret = GetDuration(duration);
    reply.WriteInt32(duration);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetApiVersion(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    int32_t apiVersion = -1;
    int32_t ret = GetApiVersion(apiVersion);
    reply.WriteInt32(apiVersion);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetPlaybackSpeed(MessageParcel &data, MessageParcel &reply)
{
    int32_t mode = data.ReadInt32();
    reply.WriteInt32(SetPlaybackSpeed(static_cast<PlaybackRateMode>(mode)));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetPlaybackRate(MessageParcel &data, MessageParcel &reply)
{
    float rate = data.ReadFloat();
    reply.WriteInt32(SetPlaybackRate(rate));
    return MSERR_OK;
}
 
int32_t PlayerServiceStub::SetMediaSource(MessageParcel &data, MessageParcel &reply)
{
    std::string url = data.ReadString();
    auto mapSize = data.ReadUint32();
    std::map<std::string, std::string> header;
    if (mapSize >= MAX_MAP_SIZE) {
        MEDIA_LOGI("Exceeded maximum table size limit");
        return MSERR_INVALID_OPERATION;
    }
    for (size_t i = 0; i < mapSize; i++) {
        auto kstr = data.ReadString();
        auto vstr = data.ReadString();
        header.emplace(kstr, vstr);
    }
    std::string mimeType = data.ReadString();
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(url, header);
    CHECK_AND_RETURN_RET_LOG(mediaSource != nullptr, MSERR_INVALID_VAL, "mediaSource is nullptr");
    mediaSource->SetMimeType(mimeType);
    if (sourceLoader_ != nullptr) {
        mediaSource->sourceLoader_ = std::move(sourceLoader_);
    }
    int32_t fd = -1;
    if (mimeType == AVMimeType::APPLICATION_M3U8) {
        fd = data.ReadFileDescriptor();
        MEDIA_LOGI("fd : %d", fd);
    }
    std::string uri = mediaSource->url;
    size_t fdHeadPos = uri.find("fd://");
    size_t fdTailPos = uri.find("?");
    if (mimeType == AVMimeType::APPLICATION_M3U8 && fdHeadPos != std::string::npos &&
        fdTailPos != std::string::npos) {
        mediaSource->url = "fd://" + std::to_string(fd) + uri.substr(fdTailPos);
    }
    int32_t ret = ReadMediaStreamListFromMessageParcel(data, mediaSource);
    if (ret != MSERR_OK) {
        MEDIA_LOGE("ReadMediaStreamListFromMessageParcel failed");
        if (fd != -1) {
            (void)::close(fd);
        }
        return ret;
    }
    struct AVPlayStrategy strategy;
    ReadPlayStrategyFromMessageParcel(data, strategy);
    bool enable = data.ReadBool();
    mediaSource->enableOfflineCache(enable);
    reply.WriteInt32(SetMediaSource(mediaSource, strategy));
    if (mimeType == AVMimeType::APPLICATION_M3U8) {
        (void)::close(fd);
    }
    return MSERR_OK;
}

int32_t PlayerServiceStub::ReadMediaStreamListFromMessageParcel(
    MessageParcel &data, const std::shared_ptr<AVMediaSource> &mediaSource)
{
    uint32_t mediaStreamLength = data.ReadUint32();
    if (mediaStreamLength > MAX_MEDIA_STREAM_LIST_SIZE) {
        MEDIA_LOGW("Exceeded MAX_MEDIA_STREAM_LIST_SIZE limit");
        return MSERR_INVALID_OPERATION;
    }
    for (uint32_t i = 0; i < mediaStreamLength; i++) {
        struct AVPlayMediaStream mediaStream;
        mediaStream.url = data.ReadString();
        mediaStream.width = data.ReadUint32();
        mediaStream.height = data.ReadUint32();
        mediaStream.bitrate = data.ReadUint32();
        mediaSource->AddMediaStream(mediaStream);
    }
    return MSERR_OK;
}

void PlayerServiceStub::ReadPlayStrategyFromMessageParcel(MessageParcel &data, AVPlayStrategy &strategy)
{
    strategy.preferredWidth = data.ReadUint32();
    strategy.preferredHeight = data.ReadUint32();
    strategy.preferredBufferDuration = data.ReadUint32();
    strategy.preferredBufferDurationForPlaying = data.ReadDouble();
    strategy.thresholdForAutoQuickPlay = data.ReadDouble();
    strategy.preferredHdr = data.ReadBool();
    strategy.showFirstFrameOnPrepare = data.ReadBool();
    strategy.enableSuperResolution = data.ReadBool();
    strategy.enableCameraPostprocessing = data.ReadBool();
    strategy.mutedMediaType = static_cast<OHOS::Media::MediaType>(data.ReadInt32());
    strategy.preferredAudioLanguage = data.ReadString();
    strategy.preferredSubtitleLanguage = data.ReadString();
    strategy.keepDecodingOnMute = data.ReadBool();
}

int32_t PlayerServiceStub::GetPlaybackSpeed(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    PlaybackRateMode mode = SPEED_FORWARD_1_00_X;
    int32_t ret = GetPlaybackSpeed(mode);
    reply.WriteInt32(mode);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetPlaybackRate(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    float rate = 1.0f;
    int32_t ret = GetPlaybackRate(rate);
    reply.WriteFloat(rate);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::SelectBitRate(MessageParcel &data, MessageParcel &reply)
{
    int32_t bitrate = data.ReadInt32();
    reply.WriteInt32(SelectBitRate(static_cast<uint32_t>(bitrate)));
    return MSERR_OK;
}

#ifdef SUPPORT_VIDEO
int32_t PlayerServiceStub::SetVideoSurface(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "object is nullptr");

    sptr<IBufferProducer> producer = iface_cast<IBufferProducer>(object);
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, MSERR_NO_MEMORY, "failed to convert object to producer");

    sptr<Surface> surface = Surface::CreateSurfaceAsProducer(producer);
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_NO_MEMORY, "failed to create surface");

    std::string format = data.ReadString();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " surfaceFormat is %{public}s!", FAKE_POINTER(this), format.c_str());
    (void)surface->SetUserData("SURFACE_FORMAT", format);
    reply.WriteInt32(SetVideoSurface(surface));
    return MSERR_OK;
}
#endif

int32_t PlayerServiceStub::SetDecryptConfig(MessageParcel &data, MessageParcel &reply)
{
    MEDIA_LOGI("PlayerServiceStub SetDecryptConfig");
#ifdef SUPPORT_AVPLAYER_DRM
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "KeySessionServiceProxy object is nullptr");
    bool svp = data.ReadBool();

    sptr<DrmStandard::MediaKeySessionServiceProxy> keySessionServiceProxy =
        iface_cast<DrmStandard::MediaKeySessionServiceProxy>(object);
    if (keySessionServiceProxy != nullptr) {
        MEDIA_LOGD("And it's count is: %{public}d", keySessionServiceProxy->GetSptrRefCount());
        reply.WriteInt32(SetDecryptConfig(keySessionServiceProxy, svp));
        return MSERR_OK;
    }
    MEDIA_LOGE("PlayerServiceStub keySessionServiceProxy is nullptr!");
    return MSERR_INVALID_VAL;
#else
    (void)data;
    (void)reply;
    return 0;
#endif
}

int32_t PlayerServiceStub::IsPlaying(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteBool(IsPlaying());
    return MSERR_OK;
}

int32_t PlayerServiceStub::IsLooping(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteBool(IsLooping());
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetLooping(MessageParcel &data, MessageParcel &reply)
{
    bool loop = data.ReadBool();
    reply.WriteInt32(SetLooping(loop));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetParameter(MessageParcel &data, MessageParcel &reply)
{
    Format param;
    (void)MediaParcel::Unmarshalling(data, param);

    reply.WriteInt32(SetParameter(param));

    return MSERR_OK;
}

int32_t PlayerServiceStub::IsSeekContinuousSupported(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteBool(IsSeekContinuousSupported());
    return MSERR_OK;
}

int32_t PlayerServiceStub::DestroyStub(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(DestroyStub());
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetPlayerCallback(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    reply.WriteInt32(SetPlayerCallback());
    return MSERR_OK;
}

int32_t PlayerServiceStub::SelectTrack(MessageParcel &data, MessageParcel &reply)
{
    int32_t index = data.ReadInt32();
    int32_t mode = data.ReadInt32();
    reply.WriteInt32(SelectTrack(index, static_cast<PlayerSwitchMode>(mode)));
    return MSERR_OK;
}

int32_t PlayerServiceStub::DeselectTrack(MessageParcel &data, MessageParcel &reply)
{
    int32_t index = data.ReadInt32();
    reply.WriteInt32(DeselectTrack(index));
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetCurrentTrack(MessageParcel &data, MessageParcel &reply)
{
    int32_t trackType = data.ReadInt32();
    int32_t index = -1;
    int32_t ret = GetCurrentTrack(trackType, index);
    reply.WriteInt32(index);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetMediaMuted(MessageParcel &data, MessageParcel &reply)
{
    int32_t mediaType = data.ReadInt32();
    bool isMuted = data.ReadBool();
    int32_t ret = SetMediaMuted(static_cast<OHOS::Media::MediaType>(mediaType), isMuted);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetMediaMuted(OHOS::Media::MediaType mediaType, bool isMuted)
{
    MediaTrace trace("PlayerServiceStub::SetMediaMuted");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetMediaMuted(mediaType, isMuted);
}

int32_t PlayerServiceStub::SetPlaybackStrategy(MessageParcel &data, MessageParcel &reply)
{
    struct AVPlayStrategy avPlaybackStrategy = {
        .preferredWidth = data.ReadUint32(),
        .preferredHeight = data.ReadUint32(),
        .preferredBufferDuration = data.ReadUint32(),
        .preferredBufferDurationForPlaying = data.ReadDouble(),
        .thresholdForAutoQuickPlay = data.ReadDouble(),
        .preferredHdr = data.ReadBool(),
        .showFirstFrameOnPrepare = data.ReadBool(),
        .enableSuperResolution = data.ReadBool(),
        .enableCameraPostprocessing = data.ReadBool(),
        .mutedMediaType = static_cast<OHOS::Media::MediaType>(data.ReadInt32()),
        .preferredAudioLanguage = data.ReadString(),
        .preferredSubtitleLanguage = data.ReadString(),
        .keepDecodingOnMute = data.ReadBool()
    };
    reply.WriteInt32(SetPlaybackStrategy(avPlaybackStrategy));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetPlaybackStrategy(AVPlayStrategy playbackStrategy)
{
    MediaTrace trace("PlayerServiceStub::SetPlaybackStrategy");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetPlaybackStrategy(playbackStrategy);
}

int32_t PlayerServiceStub::SetSuperResolution(MessageParcel &data, MessageParcel &reply)
{
    bool enabled = data.ReadBool();
    reply.WriteInt32(SetSuperResolution(enabled));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetSuperResolution(bool enabled)
{
    MediaTrace trace("Stub::SetSuperResolution");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetSuperResolution(enabled);
}

int32_t PlayerServiceStub::SetVideoWindowSize(MessageParcel &data, MessageParcel &reply)
{
    int32_t width = data.ReadInt32();
    int32_t height = data.ReadInt32();
    reply.WriteInt32(SetVideoWindowSize(width, height));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetVideoWindowSize(int32_t width, int32_t height)
{
    MediaTrace trace("Stub::SetVideoWindowSize");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetVideoWindowSize(width, height);
}

int32_t PlayerServiceStub::SetMaxAmplitudeCbStatus(bool status)
{
    MediaTrace trace("PlayerServiceStub::SetMaxAmplitudeCbStatus");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetMaxAmplitudeCbStatus(status);
}

int32_t PlayerServiceStub::SetMaxAmplitudeCbStatus(MessageParcel &data, MessageParcel &reply)
{
    bool status = data.ReadInt32();
    reply.WriteInt32(SetMaxAmplitudeCbStatus(status));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetDeviceChangeCbStatus(bool status)
{
    MediaTrace trace("PlayerServiceStub::SetDeviceChangeCbStatus");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetDeviceChangeCbStatus(status);
}
 
int32_t PlayerServiceStub::SetDeviceChangeCbStatus(MessageParcel &data, MessageParcel &reply)
{
    bool status = data.ReadInt32();
    reply.WriteInt32(SetDeviceChangeCbStatus(status));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetSeiMessageCbStatus(bool status, const std::vector<int32_t> &payloadTypes)
{
    MediaTrace trace("PlayerServiceStub::SetSeiMessageCbStatus");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetSeiMessageCbStatus(status, payloadTypes);
}

int32_t PlayerServiceStub::SetSeiMessageCbStatus(MessageParcel &data, MessageParcel &reply)
{
    bool status = data.ReadBool();
    int32_t payloadTypesSize = data.ReadInt32();
    CHECK_AND_RETURN_RET_LOG(static_cast<size_t>(payloadTypesSize) <= MAX_PAYLOAD_TYPES_SIZE,
        MSERR_INVALID_OPERATION, "Invalid payloadTypes size");
    std::vector<int32_t> payloadTypes;
    for (int32_t i = 0; i < payloadTypesSize; ++i) {
        payloadTypes.push_back(data.ReadInt32());
    }
    reply.WriteInt32(SetSeiMessageCbStatus(status, payloadTypes));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetReopenFd(MessageParcel &data, MessageParcel &reply)
{
    int32_t fd = data.ReadFileDescriptor();
    reply.WriteInt32(SetReopenFd(fd));
    (void)::close(fd);
    return MSERR_OK;
}
 
int32_t PlayerServiceStub::EnableCameraPostprocessing(MessageParcel &data, MessageParcel &reply)
{
    reply.WriteInt32(EnableCameraPostprocessing());
    return MSERR_OK;
}
 
int32_t PlayerServiceStub::EnableCameraPostprocessing()
{
    MediaTrace trace("Stub::EnableCameraPostprocessing");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->EnableCameraPostprocessing();
}

int32_t PlayerServiceStub::SetCameraPostprocessing(MessageParcel &data, MessageParcel &reply)
{
    bool isOpen = data.ReadBool();
    reply.WriteInt32(SetCameraPostprocessing(isOpen));
    return MSERR_OK;
}
 
int32_t PlayerServiceStub::SetCameraPostprocessing(bool isOpen)
{
    MediaTrace trace("Stub::SetCameraPostprocessing");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetCameraPostprocessing(isOpen);
}

int32_t PlayerServiceStub::EnableReportMediaProgress(bool enable)
{
    MediaTrace trace("PlayerServiceStub::EnableReportMediaProgress");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->EnableReportMediaProgress(enable);
}

int32_t PlayerServiceStub::EnableReportMediaProgress(MessageParcel &data, MessageParcel &reply)
{
    bool enable = data.ReadBool();
    reply.WriteInt32(EnableReportMediaProgress(enable));
    return MSERR_OK;
}

int32_t PlayerServiceStub::EnableReportAudioInterrupt(bool enable)
{
    MediaTrace trace("PlayerServiceStub::EnableReportAudioInterrupt");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->EnableReportAudioInterrupt(enable);
}

int32_t PlayerServiceStub::EnableReportAudioInterrupt(MessageParcel &data, MessageParcel &reply)
{
    bool enable = data.ReadBool();
    reply.WriteInt32(EnableReportAudioInterrupt(enable));
    return MSERR_OK;
}

int32_t PlayerServiceStub::ForceLoadVideo(bool status)
{
    MediaTrace trace("PlayerServiceStub::ForceLoadVideo");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->ForceLoadVideo(status);
}

int32_t PlayerServiceStub::ForceLoadVideo(MessageParcel &data, MessageParcel &reply)
{
    reply.WriteInt32(ForceLoadVideo(data.ReadBool()));
    return MSERR_OK;
}

int32_t PlayerServiceStub::SetLoudnessGain(float loudnessGain)
{
    MediaTrace trace("PlayerServiceStub::SetLoudnessGain");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->SetLoudnessGain(loudnessGain);
}

int32_t PlayerServiceStub::SetLoudnessGain(MessageParcel &data, MessageParcel &reply)
{
    reply.WriteInt32(SetLoudnessGain(data.ReadFloat()));
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetGlobalInfo(std::shared_ptr<Meta> &globalInfo)
{
    MediaTrace trace("PlayerServiceStub::GetGlobalInfo");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetGlobalInfo(globalInfo);
}

int32_t PlayerServiceStub::GetGlobalInfo(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    std::shared_ptr<Meta> globalInfo;
    int32_t ret = GetGlobalInfo(globalInfo);
    CHECK_AND_RETURN_RET_LOG(globalInfo != nullptr, MSERR_INVALID_VAL, "globalInfo is nullptr");
    globalInfo->ToParcel(reply);
    reply.WriteInt32(ret);
 
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetMediaDescription(MessageParcel &data, MessageParcel &reply)
{
    (void)data;
    Format format;
    (void)MediaParcel::Unmarshalling(data, format);
    int32_t ret = GetMediaDescription(format);
    (void)MediaParcel::Marshalling(reply, format);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetMediaDescription(Format &format)
{
    MediaTrace trace("PlayerServiceStub::GetMediaDescription");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetMediaDescription(format);
}

int32_t PlayerServiceStub::GetTrackDescription(MessageParcel &data, MessageParcel &reply)
{
    Format format;
    int32_t ret = GetTrackDescription(format, data.ReadUint32());
    (void)MediaParcel::Marshalling(reply, format);
    reply.WriteInt32(ret);
    return MSERR_OK;
}

int32_t PlayerServiceStub::GetTrackDescription(Format &format, uint32_t trackIndex)
{
    MediaTrace trace("PlayerServiceStub::GetTrackDescription");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");
    return playerServer_->GetTrackDescription(format, trackIndex);
}

int32_t PlayerServiceStub::RegisterDeviceCapability(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    reply.WriteInt32(RegisterDeviceCapability(object));
    return MSERR_OK;
}
 
int32_t PlayerServiceStub::RegisterDeviceCapability(const sptr<IRemoteObject> &object)
{
    MediaTrace trace("PlayerServiceStub::RegisterDeviceCapability");
    MEDIA_LOGI("PlayerServiceStub RegisterDeviceCapability");
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "registerDeviceCapability object is nullptr");
    CHECK_AND_RETURN_RET_LOG(playerServer_ != nullptr, MSERR_NO_MEMORY, "player server is nullptr");

    sptr<IStandardDolbyPassthrough> proxy = iface_cast<IStandardDolbyPassthrough>(object);
    CHECK_AND_RETURN_RET_LOG(proxy != nullptr, MSERR_NO_MEMORY, "failed to convert DolbyPassthroughProxy");
    std::shared_ptr<IDolbyPassthrough> dolbyPassthrough = std::make_shared<DolbyPassthroughCallback>(proxy);
    CHECK_AND_RETURN_RET_LOG(dolbyPassthrough != nullptr, MSERR_NO_MEMORY,
        "failed to new DolbyPassthroughCallbackCallback");
    return playerServer_->SetDolbyPassthroughCallback(dolbyPassthrough);
}
} // namespace Media
} // namespace OHOS

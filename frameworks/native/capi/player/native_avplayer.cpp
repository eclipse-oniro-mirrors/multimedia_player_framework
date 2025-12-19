/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <mutex>
#include <securec.h>
#ifdef SUPPORT_AVPLAYER_DRM
#include "native_drm_object.h"
#endif
#include "media_log.h"
#include "media_errors.h"
#include "native_mfmagic.h"
#include "native_player_magic.h"
#include "native_window.h"
#include "avplayer.h"
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "NativeAVPlayer"};
    constexpr uint32_t ERROR_CODE_API9_MAP_LENGTH = 23;
    constexpr uint32_t STATE_MAP_LENGTH = 9;
    constexpr uint32_t INFO_TYPE_LENGTH = 19;
    constexpr int32_t UNSUPPORT_FORMAT_ERROR_CODE = 331350544;
    constexpr int32_t AVPLAYER_ERR_UNSUPPORT = 9;
}

using namespace OHOS::Media;
using namespace OHOS::DrmStandard;
class NativeAVPlayerCallback;

const char* OH_PLAYER_MESSAGE_TYPE = PlayerKeys::PLAYER_MESSAGE_TYPE.data();
const char* OH_PLAYER_IS_LIVE_STREAM = PlayerKeys::PLAYER_IS_LIVE_STREAM.data();
const char* OH_PLAYER_SEEK_POSITION = PlayerKeys::PLAYER_SEEK_POSITION.data();
const char* OH_PLAYER_PLAYBACK_SPEED = PlayerKeys::PLAYER_PLAYBACK_SPEED.data();
const char* OH_PLAYER_PLAYBACK_RATE = PlayerKeys::PLAYER_PLAYBACK_RATE.data();
const char* OH_PLAYER_BITRATE = PlayerKeys::PLAYER_BITRATE_DONE.data();
const char* OH_PLAYER_CURRENT_POSITION = PlayerKeys::PLAYER_CURRENT_POSITION.data();
const char* OH_PLAYER_DURATION = PlayerKeys::PLAYER_DURATION.data();
const char* OH_PLAYER_STATE = PlayerKeys::PLAYER_STATE_CHANGE.data();
const char* OH_PLAYER_STATE_CHANGE_REASON = PlayerKeys::PLAYER_STATE_CHANGED_REASON.data();
const char* OH_PLAYER_VOLUME = PlayerKeys::PLAYER_VOLUME_LEVEL.data();
const char* OH_PLAYER_BITRATE_ARRAY = PlayerKeys::PLAYER_AVAILABLE_BITRATES.data();
const char* OH_PLAYER_AUDIO_INTERRUPT_TYPE = PlayerKeys::AUDIO_INTERRUPT_TYPE.data();
const char* OH_PLAYER_AUDIO_INTERRUPT_FORCE = PlayerKeys::AUDIO_INTERRUPT_FORCE.data();
const char* OH_PLAYER_AUDIO_INTERRUPT_HINT = PlayerKeys::AUDIO_INTERRUPT_HINT.data();
const char* OH_PLAYER_AUDIO_DEVICE_CHANGE_REASON = PlayerKeys::AUDIO_DEVICE_CHANGE_REASON.data();
const char* OH_PLAYER_BUFFERING_TYPE = PlayerKeys::PLAYER_BUFFERING_TYPE.data();
const char* OH_PLAYER_BUFFERING_VALUE = PlayerKeys::PLAYER_BUFFERING_VALUE.data();
const char* OH_PLAYER_VIDEO_WIDTH = PlayerKeys::PLAYER_WIDTH.data();
const char* OH_PLAYER_VIDEO_HEIGHT = PlayerKeys::PLAYER_HEIGHT.data();
const char* OH_PLAYER_TRACK_INDEX = PlayerKeys::PLAYER_TRACK_INDEX.data();
const char* OH_PLAYER_TRACK_IS_SELECT = PlayerKeys::PLAYER_IS_SELECT.data();
const char* OH_PLAYER_SUBTITLE_TEXT = PlayerKeys::SUBTITLE_TEXT.data();
const char* OH_PLAYER_SUBTITLE_PTS = PlayerKeys::SUBTITLE_PTS.data();
const char* OH_PLAYER_SUBTITLE_DURATION = PlayerKeys::SUBTITLE_DURATION.data();
const char* OH_PLAYER_MD_KEY_HAS_VIDEO = PlayerKeys::PLAYER_HAS_VIDEO.data();
const char* OH_PLAYER_MD_KEY_HAS_AUDIO = PlayerKeys::PLAYER_HAS_AUDIO.data();
const char* OH_PLAYER_MD_KEY_HAS_SUBTITLE = PlayerKeys::PLAYER_HAS_SUBTITLE.data();
const char* OH_PLAYER_MD_KEY_TRACK_INDEX = PlayerKeys::PLAYER_TRACK_INDEX.data();

const char* OH_MEDIA_EVENT_INFO_PREPARE_DURATION = PlaybackMetricsKey::PREPARE_DURATION.data();
const char* OH_MEDIA_EVENT_INFO_RESOURCE_CONNECTION_DURATION = PlaybackMetricsKey::RESOURCE_CONNECTION_DURATION.data();
const char* OH_MEDIA_EVENT_INFO_FIRST_FRAME_DECAPSULATION_DURATION =
    PlaybackMetricsKey::FIRST_FRAME_DECAPSULATION_DURATION.data();
const char* OH_MEDIA_EVENT_INFO_TOTAL_PLAYING_TIME = PlaybackMetricsKey::TOTAL_PLAYING_TIME.data();
const char* OH_MEDIA_EVENT_INFO_DOWNLOAD_REQUEST_COUNT = PlaybackMetricsKey::DOWNLOAD_REQUESTS_COUNT.data();
const char* OH_MEDIA_EVENT_INFO_DOWNLOAD_TOTAL_TIME = PlaybackMetricsKey::TOTAL_DOWNLOAD_TIME.data();
const char* OH_MEDIA_EVENT_INFO_DOWNLOAD_TOTAL_SIZE = PlaybackMetricsKey::TOTAL_DOWNLOAD_SIZE.data();
const char* OH_MEDIA_EVENT_INFO_STALLING_COUNT = PlaybackMetricsKey::STALLING_COUNT.data();
const char* OH_MEDIA_EVENT_INFO_TOTAL_STALLING_TIME = PlaybackMetricsKey::TOTAL_STALLING_TIME.data();

typedef struct PlayerErrorCodeApi9Convert {
    MediaServiceExtErrCodeAPI9 errorCodeApi9;
    OH_AVErrCode avErrorCode;
} PlayerErrorCodeApi9Convert;

typedef struct StateConvert {
    PlayerStates playerStates;
    AVPlayerState avPlayerState;
} StateConvert;

typedef struct PlayerOnInfoTypeConvert {
    PlayerOnInfoType playerOnInfoType;
    AVPlayerOnInfoType aVPlayerOnInfoType;
} PlayerOnInfoTypeConvert;

static const PlayerErrorCodeApi9Convert ERROR_CODE_API9_MAP[ERROR_CODE_API9_MAP_LENGTH] = {
    {MSERR_EXT_API9_OK, AV_ERR_OK},
    {MSERR_EXT_API9_NO_PERMISSION, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_PERMISSION_DENIED, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_INVALID_PARAMETER, AV_ERR_INVALID_VAL},
    {MSERR_EXT_API9_UNSUPPORT_CAPABILITY, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_NO_MEMORY, AV_ERR_NO_MEMORY},
    {MSERR_EXT_API9_OPERATE_NOT_PERMIT, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_IO, AV_ERR_IO},
    {MSERR_EXT_API9_TIMEOUT, AV_ERR_TIMEOUT},
    {MSERR_EXT_API9_SERVICE_DIED, AV_ERR_SERVICE_DIED},
    {MSERR_EXT_API9_UNSUPPORT_FORMAT, AV_ERR_UNSUPPORT},
    {MSERR_EXT_API9_AUDIO_INTERRUPTED, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API14_IO_CANNOT_FIND_HOST, AV_ERR_IO_CANNOT_FIND_HOST},
    {MSERR_EXT_API14_IO_CONNECTION_TIMEOUT, AV_ERR_IO_CONNECTION_TIMEOUT},
    {MSERR_EXT_API14_IO_NETWORK_ABNORMAL, AV_ERR_IO_NETWORK_ABNORMAL},
    {MSERR_EXT_API14_IO_NETWORK_UNAVAILABLE, AV_ERR_IO_NETWORK_UNAVAILABLE},
    {MSERR_EXT_API14_IO_NO_PERMISSION, AV_ERR_IO_NO_PERMISSION},
    {MSERR_EXT_API14_IO_NETWORK_ACCESS_DENIED, AV_ERR_IO_NETWORK_ACCESS_DENIED},
    {MSERR_EXT_API14_IO_RESOURE_NOT_FOUND, AV_ERR_IO_RESOURCE_NOT_FOUND},
    {MSERR_EXT_API14_IO_SSL_CLIENT_CERT_NEEDED, AV_ERR_IO_SSL_CLIENT_CERT_NEEDED},
    {MSERR_EXT_API14_IO_SSL_CONNECT_FAIL, AV_ERR_IO_SSL_CONNECT_FAIL},
    {MSERR_EXT_API14_IO_SSL_SERVER_CERT_UNTRUSTED, AV_ERR_IO_SSL_SERVER_CERT_UNTRUSTED},
    {MSERR_EXT_API14_IO_UNSUPPORTTED_REQUEST, AV_ERR_IO_UNSUPPORTED_REQUEST},
};

static const StateConvert STATE_MAP[STATE_MAP_LENGTH] = {
    { PLAYER_STATE_ERROR, AV_ERROR},
    { PLAYER_IDLE, AV_IDLE },
    { PLAYER_INITIALIZED, AV_INITIALIZED },
    { PLAYER_PREPARED, AV_PREPARED },
    { PLAYER_STARTED, AV_PLAYING },
    { PLAYER_PAUSED, AV_PAUSED },
    { PLAYER_STOPPED, AV_STOPPED },
    { PLAYER_PLAYBACK_COMPLETE, AV_COMPLETED },
    { PLAYER_RELEASED, AV_RELEASED },
};

static const PlayerOnInfoTypeConvert ON_INFO_TYPE[INFO_TYPE_LENGTH] = {
    { INFO_TYPE_SEEKDONE, AV_INFO_TYPE_SEEKDONE },
    { INFO_TYPE_SPEEDDONE, AV_INFO_TYPE_SPEEDDONE },
    { INFO_TYPE_BITRATEDONE, AV_INFO_TYPE_BITRATEDONE },
    { INFO_TYPE_EOS, AV_INFO_TYPE_EOS },
    { INFO_TYPE_STATE_CHANGE, AV_INFO_TYPE_STATE_CHANGE },
    { INFO_TYPE_POSITION_UPDATE, AV_INFO_TYPE_POSITION_UPDATE },
    { INFO_TYPE_MESSAGE, AV_INFO_TYPE_MESSAGE },
    { INFO_TYPE_VOLUME_CHANGE, AV_INFO_TYPE_VOLUME_CHANGE },
    { INFO_TYPE_RESOLUTION_CHANGE, AV_INFO_TYPE_RESOLUTION_CHANGE },
    { INFO_TYPE_BUFFERING_UPDATE, AV_INFO_TYPE_BUFFERING_UPDATE },
    { INFO_TYPE_BITRATE_COLLECT, AV_INFO_TYPE_BITRATE_COLLECT },
    { INFO_TYPE_INTERRUPT_EVENT, AV_INFO_TYPE_INTERRUPT_EVENT },
    { INFO_TYPE_DURATION_UPDATE, AV_INFO_TYPE_DURATION_UPDATE },
    { INFO_TYPE_IS_LIVE_STREAM, AV_INFO_TYPE_IS_LIVE_STREAM },
    { INFO_TYPE_TRACKCHANGE, AV_INFO_TYPE_TRACKCHANGE },
    { INFO_TYPE_TRACK_INFO_UPDATE, AV_INFO_TYPE_TRACK_INFO_UPDATE },
    { INFO_TYPE_SUBTITLE_UPDATE_INFO, AV_INFO_TYPE_SUBTITLE_UPDATE },
    { INFO_TYPE_AUDIO_DEVICE_CHANGE, AV_INFO_TYPE_AUDIO_OUTPUT_DEVICE_CHANGE},
    { INFO_TYPE_RATEDONE, AV_INFO_TYPE_PLAYBACK_RATE_DONE },
};

static OH_AVErrCode MSErrCodeToAVErrCodeApi9(MediaServiceExtErrCodeAPI9 errorCode)
{
    for (uint32_t i = 0; i < ERROR_CODE_API9_MAP_LENGTH; i++) {
        if (ERROR_CODE_API9_MAP[i].errorCodeApi9 == errorCode) {
            return ERROR_CODE_API9_MAP[i].avErrorCode;
        }
    }
    return AV_ERR_UNKNOWN;
}

struct PlayerObject : public OH_AVPlayer {
    explicit PlayerObject(const std::shared_ptr<Player> &player)
        : player_(player) {}
    ~PlayerObject() = default;

    void StartListenCurrentResource();
    void PauseListenCurrentResource();

    const std::shared_ptr<Player> player_ = nullptr;
    std::shared_ptr<NativeAVPlayerCallback> callback_ = nullptr;
    std::multimap<std::vector<uint8_t>, std::vector<uint8_t>> localDrmInfos_;
    std::atomic<bool> isReleased_ = false;
};

#ifdef SUPPORT_AVPLAYER_DRM
class DrmSystemInfoCallback {
public:
    virtual ~DrmSystemInfoCallback() = default;
    virtual int32_t SetDrmSystemInfoCallback(Player_MediaKeySystemInfoCallback drmSystemInfoCallback) = 0;
    virtual int32_t GetDrmSystemInfos(const Format &infoBody,
        DRM_MediaKeySystemInfo *mediaKeySystemInfo, struct PlayerObject *playerObj) = 0;
};
#endif

class NativeAVPlayerOnErrorCallback {
public:
    NativeAVPlayerOnErrorCallback(OH_AVPlayerOnErrorCallback callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeAVPlayerOnErrorCallback() = default;

    void OnError(OH_AVPlayer *player, int32_t errorCode, const std::string &errorMsg)
    {
        CHECK_AND_RETURN(player != nullptr && callback_ != nullptr);
        callback_(player, errorCode, errorMsg.c_str(), userData_);
    }

private:
    OH_AVPlayerOnErrorCallback callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeAVPlayerOnInfoCallback {
public:
    NativeAVPlayerOnInfoCallback(OH_AVPlayerOnInfoCallback callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeAVPlayerOnInfoCallback() = default;

    void OnInfo(OH_AVPlayer *player, AVPlayerOnInfoType infoType, OH_AVFormat* infoBody)
    {
        CHECK_AND_RETURN(player != nullptr && callback_ != nullptr);
        callback_(player, infoType, infoBody, userData_);
    }

private:
    OH_AVPlayerOnInfoCallback callback_ = nullptr;
    void *userData_ = nullptr;
};

#ifdef SUPPORT_AVPLAYER_DRM
class NativeAVPlayerCallback : public PlayerCallback, public DrmSystemInfoCallback {
public:
    using OnInfoFunc = std::function<void(const int32_t, const Format &)>;
    NativeAVPlayerCallback(OH_AVPlayer *player, AVPlayerCallback callback);

    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody) override;
    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    int32_t SetDrmSystemInfoCallback(Player_MediaKeySystemInfoCallback drmSystemInfoCallback) override;
    int32_t GetDrmSystemInfos(const Format &infoBody,
        DRM_MediaKeySystemInfo *mediaKeySystemInfo, struct PlayerObject *playerObj) override;
#else
class NativeAVPlayerCallback : public PlayerCallback {
public:
    using OnInfoFunc = std::function<void(const int32_t, const Format &)>;
    NativeAVPlayerCallback(OH_AVPlayer *player, AVPlayerCallback callback);

    void OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody) override;
    void OnError(int32_t errorCode, const std::string &errorMsg) override;
#endif

public:
    int32_t SetPlayCallback(AVPlayerCallback callback);
    int32_t SetOnErrorCallback(OH_AVPlayerOnErrorCallback callback, void *userData);
    int32_t SetOnInfoCallback(OH_AVPlayerOnInfoCallback callback, void *userData);
    void Start();
    void Pause();

private:
    void OnSeekDoneCb(const int32_t extra, const Format &infoBody);
    void OnSpeedDoneCb(const int32_t extra, const Format &infoBody);
    void OnPlaybackRateDoneCb(const int32_t extra, const Format &infoBody);
    void OnBitRateDoneCb(const int32_t extra, const Format &infoBody);
    void OnEosCb(const int32_t extra, const Format &infoBody);
    void OnStateChangeCb(const int32_t extra, const Format &infoBody);
    void OnPositionUpdateCb(const int32_t extra, const Format &infoBody);
    void OnVolumeChangeCb(const int32_t extra, const Format &infoBody);
    void OnMessageCb(const int32_t extra, const Format &infoBody);
    void OnStartRenderFrameCb() const;
    void OnVideoSizeChangedCb(const int32_t extra, const Format &infoBody);
    void OnBufferingUpdateCb(const int32_t extra, const Format &infoBody);
    void OnBitRateCollectedCb(const int32_t extra, const Format &infoBody);
    void OnAudioInterruptCb(const int32_t extra, const Format &infoBody);
    void OnDurationUpdateCb(const int32_t extra, const Format &infoBody);
    void OnNotifyIsLiveStream(const int32_t extra, const Format &infoBody);
    void OnTrackChangedCb(const int32_t extra, const Format &infoBody);
    void OnTrackInfoUpdate(const int32_t extra, const Format &infoBody);
    void OnSubtitleInfoCb(const int32_t extra, const Format &infoBody);
    void OnAudioDeviceChangeCb(const int32_t extra, const Format &infoBody);
    void OnDrmInfoUpdatedCb(const int32_t extra, const Format &infoBody);

private:
    std::mutex mutex_;
    std::atomic<bool> isReleased_ = false;
    std::atomic<bool> isSourceLoaded_ = false;
    struct OH_AVPlayer *player_ = nullptr;
    std::shared_ptr<NativeAVPlayerOnErrorCallback> errorCallback_ = nullptr;
    std::shared_ptr<NativeAVPlayerOnInfoCallback> infoCallback_ = nullptr;
    std::map<uint32_t, OnInfoFunc> onInfoFuncs_;
    struct AVPlayerCallback callback_ = { .onInfo = nullptr, .onError = nullptr };
    Player_MediaKeySystemInfoCallback drmsysteminfocallback_ = nullptr;
};

class NativeAVDataSource : public OHOS::Media::IMediaDataSource {
public:
    NativeAVDataSource(OH_AVDataSourceExt* dataSourceExt, void* userData)
        : dataSourceExt_(dataSourceExt), userData_(userData) {}
    
    virtual ~NativeAVDataSource() = default;

    int32_t ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos = -1)
    {
        if (mem == nullptr || dataSourceExt_ == nullptr) {
            MEDIA_LOGE("NativeAVDataSource ReadAt mem or dataSourceExt_ is nullptr");
            return 0;
        }
        std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(
            mem->GetBase(), mem->GetSize(), mem->GetSize()
        );
        OH_AVBuffer avBuffer(buffer);
        return dataSourceExt_->readAt(&avBuffer, length, pos, userData_);
    }

    int32_t GetSize(int64_t &size)
    {
        if (dataSourceExt_ == nullptr) {
            MEDIA_LOGE("NativeAVDataSource GetSize dataSourceExt_ is nullptr");
            return 0;
        }
        size = dataSourceExt_->size;
        return 0;
    }

    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
    {
        return ReadAt(mem, length, pos);
    }

    int32_t ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
    {
        return ReadAt(mem, length);
    }

private:
    OH_AVDataSourceExt* dataSourceExt_ = nullptr;
    void* userData_ = nullptr;
};

void PlayerObject::StartListenCurrentResource()
{
    if (callback_ != nullptr) {
        callback_->Start();
    }
}

void PlayerObject::PauseListenCurrentResource()
{
    if (callback_ != nullptr) {
        callback_->Pause();
    }
}

NativeAVPlayerCallback::NativeAVPlayerCallback(OH_AVPlayer *player, AVPlayerCallback callback) : player_(player),
    callback_(callback) {
    MEDIA_LOGD("0x%{public}06" PRIXPTR " callback create", FAKE_POINTER(this));
    onInfoFuncs_ = {
        { INFO_TYPE_SEEKDONE,
            [this](const int32_t extra, const Format &infoBody) { OnSeekDoneCb(extra, infoBody); } },
        { INFO_TYPE_SPEEDDONE,
            [this](const int32_t extra, const Format &infoBody) { OnSpeedDoneCb(extra, infoBody); } },
        { INFO_TYPE_RATEDONE,
            [this](const int32_t extra, const Format &infoBody) { OnPlaybackRateDoneCb(extra, infoBody); } },
        { INFO_TYPE_BITRATEDONE,
            [this](const int32_t extra, const Format &infoBody) { OnBitRateDoneCb(extra, infoBody); } },
        { INFO_TYPE_EOS,
            [this](const int32_t extra, const Format &infoBody) { OnEosCb(extra, infoBody); } },
        { INFO_TYPE_STATE_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnStateChangeCb(extra, infoBody); } },
        { INFO_TYPE_POSITION_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnPositionUpdateCb(extra, infoBody); } },
        { INFO_TYPE_MESSAGE,
            [this](const int32_t extra, const Format &infoBody) { OnMessageCb(extra, infoBody);} },
        { INFO_TYPE_VOLUME_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnVolumeChangeCb(extra, infoBody); } },
        { INFO_TYPE_RESOLUTION_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnVideoSizeChangedCb(extra, infoBody); } },
        { INFO_TYPE_BUFFERING_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnBufferingUpdateCb(extra, infoBody); } },
        { INFO_TYPE_BITRATE_COLLECT,
            [this](const int32_t extra, const Format &infoBody) { OnBitRateCollectedCb(extra, infoBody); } },
        { INFO_TYPE_INTERRUPT_EVENT,
            [this](const int32_t extra, const Format &infoBody) { OnAudioInterruptCb(extra, infoBody); } },
        { INFO_TYPE_DURATION_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnDurationUpdateCb(extra, infoBody); } },
        { INFO_TYPE_IS_LIVE_STREAM,
            [this](const int32_t extra, const Format &infoBody) { OnNotifyIsLiveStream(extra, infoBody); } },
        { INFO_TYPE_TRACKCHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnTrackChangedCb(extra, infoBody); } },
        { INFO_TYPE_TRACK_INFO_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnTrackInfoUpdate(extra, infoBody); } },
        { INFO_TYPE_SUBTITLE_UPDATE_INFO,
            [this](const int32_t extra, const Format &infoBody) { OnSubtitleInfoCb(extra, infoBody); } },
        { INFO_TYPE_AUDIO_DEVICE_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnAudioDeviceChangeCb(extra, infoBody); } },
        { INFO_TYPE_DRM_INFO_UPDATED,
            [this](const int32_t extra, const Format &infoBody) { OnDrmInfoUpdatedCb(extra, infoBody); } },
    };
}

void NativeAVPlayerCallback::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    std::unique_lock<std::mutex> lock(mutex_);
    if (isReleased_.load() || player_ == nullptr) {
        MEDIA_LOGI("OnInfo() is called, type %{public}d, extra %{public}d, isReleased %{public}d",
            static_cast<int32_t>(type), extra, isReleased_.load());
        return;
    }

    if (infoCallback_ != nullptr) { // infoCallback_ precedes over callback_.onInfo
        MEDIA_LOGD("OnInfo type %{public}d extra %{public}d", type, extra);
        if (onInfoFuncs_.count(type) > 0) {
            onInfoFuncs_[type](extra, infoBody);
        } else {
            MEDIA_LOGD("0x%{public}06" PRIXPTR " OnInfo: no member func, type %{public}d extra %{public}d",
                FAKE_POINTER(this), type, extra);
        }
        return;
    }

    if (type == INFO_TYPE_DRM_INFO_UPDATED) { // process drm with independent callback
        OnDrmInfoUpdatedCb(extra, infoBody);
        return;
    }

    if (callback_.onInfo == nullptr) {
        return;
    }
    if (type == INFO_TYPE_STATE_CHANGE) {
        PlayerStates state = static_cast<PlayerStates>(extra);
        player_->state_ = state;
        for (uint32_t i = 0; i < STATE_MAP_LENGTH; i++) {
            if (STATE_MAP[i].playerStates != state) {
                continue;
            }
            int32_t convertState = STATE_MAP[i].avPlayerState;
            callback_.onInfo(player_, AV_INFO_TYPE_STATE_CHANGE, convertState);
            return;
        };
        return;
    }
    for (uint32_t i = 0; i < INFO_TYPE_LENGTH; i++) {
        if (ON_INFO_TYPE[i].playerOnInfoType == type) {
            callback_.onInfo(player_, ON_INFO_TYPE[i].aVPlayerOnInfoType, extra);
            break;
        }
    }
}

void NativeAVPlayerCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MEDIA_LOGI("OnError() is called, errorCode: %{public}d, isReleased: %{public}d, errorMsg: %{public}s",
        errorCode, isReleased_.load(), errorMsg.c_str());
    std::unique_lock<std::mutex> lock(mutex_);
    if (isReleased_.load() || player_ == nullptr) {
        return;
    }
    int32_t avErrorCode;
    if (errorCallback_) { // errorCallback_ precedes over callback_.onInfo
        MediaServiceExtErrCodeAPI9 errorCodeApi9 = MSERR_EXT_API9_OK;
        if (errorCode >= MSERR_EXT_API9_NO_PERMISSION && errorCode <= MSERR_EXT_API14_IO_UNSUPPORTTED_REQUEST) {
            errorCodeApi9 = static_cast<MediaServiceExtErrCodeAPI9>(errorCode);
        } else {
            errorCodeApi9 = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errorCode));
        }
        avErrorCode = MSErrCodeToAVErrCodeApi9(errorCodeApi9);
        std::string errorMsgExt = MSExtAVErrorToString(errorCodeApi9) + errorMsg;
        errorCallback_->OnError(player_, avErrorCode, errorMsgExt.c_str());
        return;
    }

    if (callback_.onError != nullptr) {
        // To make sure compatibility only convert for UNSUPPORT_FORMAT_ERROR_CODE
        avErrorCode = errorCode;
        if (errorCode == UNSUPPORT_FORMAT_ERROR_CODE) {
            avErrorCode = AVPLAYER_ERR_UNSUPPORT;
        }
        callback_.onError(player_, avErrorCode, errorMsg.c_str());
    }
}

#ifdef SUPPORT_AVPLAYER_DRM
int32_t NativeAVPlayerCallback::SetDrmSystemInfoCallback(Player_MediaKeySystemInfoCallback drmSystemInfoCallback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    drmsysteminfocallback_ = drmSystemInfoCallback;
    return AV_ERR_OK;
}

int32_t NativeAVPlayerCallback::GetDrmSystemInfos(const Format &infoBody,
    DRM_MediaKeySystemInfo *mediaKeySystemInfo, struct PlayerObject *playerObj)
{
    if (!infoBody.ContainKey(std::string(PlayerKeys::PLAYER_DRM_INFO_ADDR))) {
        MEDIA_LOGW("there's no drminfo-update drm_info_addr key");
        return AV_ERR_INVALID_VAL;
    }
    if (!infoBody.ContainKey(std::string(PlayerKeys::PLAYER_DRM_INFO_COUNT))) {
        MEDIA_LOGW("there's no drminfo-update drm_info_count key");
        return AV_ERR_INVALID_VAL;
    }
    uint8_t *drmInfoAddr = nullptr;
    size_t size  = 0;
    int32_t infoCount = 0;
    infoBody.GetBuffer(std::string(PlayerKeys::PLAYER_DRM_INFO_ADDR), &drmInfoAddr, size);
    CHECK_AND_RETURN_RET_LOG(drmInfoAddr != nullptr && size > 0, AV_ERR_INVALID_VAL, "get drminfo buffer failed");
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_DRM_INFO_COUNT), infoCount);
    CHECK_AND_RETURN_RET_LOG(infoCount > 0, AV_ERR_INVALID_VAL, "get drminfo count is illegal");
    DrmInfoItem *drmInfos = reinterpret_cast<DrmInfoItem*>(drmInfoAddr);
    CHECK_AND_RETURN_RET_LOG(drmInfos != nullptr, AV_ERR_INVALID_VAL, "cast drmInfos nullptr");
    for (int32_t i = 0; i < infoCount; i++) {
        DrmInfoItem temp = drmInfos[i];
        std::vector<uint8_t> uuid(temp.uuid, temp.uuid + DrmConstant::DRM_MAX_M3U8_DRM_UUID_LEN);
        if (temp.psshLen <= 0 || temp.psshLen > DrmConstant::DRM_MAX_M3U8_DRM_PSSH_LEN) {
            MEDIA_LOGW("drmInfoItem psshLen is invalid");
            continue;
        }
        std::vector<uint8_t> pssh(temp.pssh, temp.pssh + temp.psshLen);
        playerObj->localDrmInfos_.insert({ uuid, pssh });
    }
    int index = 0;
    for (auto item : playerObj->localDrmInfos_) {
        int ret = memcpy_s(mediaKeySystemInfo->psshInfo[index].uuid,
            item.first.size(), item.first.data(), item.first.size());
        int err = memcpy_s(mediaKeySystemInfo->psshInfo[index].data, item.second.size(),
            item.second.data(), item.second.size());
        CHECK_AND_RETURN_RET_LOG((err == 0 && ret == 0), AV_ERR_INVALID_VAL, "cast drmInfos nullptr");
        mediaKeySystemInfo->psshInfo[index++].dataLen = static_cast<int32_t>(item.second.size());
    }
    mediaKeySystemInfo->psshCount = static_cast<unsigned int>(index);
    return AV_ERR_OK;
}
#endif

int32_t NativeAVPlayerCallback::SetPlayCallback(AVPlayerCallback callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
    return AV_ERR_OK;
}

int32_t NativeAVPlayerCallback::SetOnErrorCallback(OH_AVPlayerOnErrorCallback callback, void *userData)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback != nullptr) {
        NativeAVPlayerOnErrorCallback *errorCallback =
            new (std::nothrow) NativeAVPlayerOnErrorCallback(callback, userData);
        CHECK_AND_RETURN_RET_LOG(errorCallback != nullptr, AV_ERR_NO_MEMORY, "errorCallback is nullptr!");
        errorCallback_ = std::shared_ptr<NativeAVPlayerOnErrorCallback>(errorCallback);
    } else {
        errorCallback_ = nullptr;
    }
    return AV_ERR_OK;
}

int32_t NativeAVPlayerCallback::SetOnInfoCallback(OH_AVPlayerOnInfoCallback callback, void *userData)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callback != nullptr) {
        NativeAVPlayerOnInfoCallback *onInfoCallback =
            new (std::nothrow) NativeAVPlayerOnInfoCallback(callback, userData);
        CHECK_AND_RETURN_RET_LOG(onInfoCallback != nullptr, AV_ERR_NO_MEMORY, "infoCallback_ is nullptr!");
        infoCallback_ = std::shared_ptr<NativeAVPlayerOnInfoCallback>(onInfoCallback);
    } else {
        infoCallback_ = nullptr;
    }
    return AV_ERR_OK;
}

void NativeAVPlayerCallback::Start()
{
    isSourceLoaded_.store(true);
}

void NativeAVPlayerCallback::Pause()
{
    isSourceLoaded_.store(false);
}

void NativeAVPlayerCallback::OnSeekDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnSeekDoneCb current source is unready");
    int32_t currentPositon = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " seekDone %{public}d", FAKE_POINTER(this), currentPositon);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnSeekDoneCb OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_SEEK_POSITION, currentPositon);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_SEEKDONE, reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnSpeedDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnSpeedDoneCb current source is unready");
    int32_t speedMode = extra;
    MEDIA_LOGI("SpeedDone %{public}d", speedMode);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnSpeedDoneCb OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_PLAYBACK_SPEED, speedMode);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_SPEEDDONE, reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnPlaybackRateDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnPlaybackRateDoneCb current source is unready");
    float rate = 0.0f;
    (void)infoBody.GetFloatValue(PlayerKeys::PLAYER_PLAYBACK_RATE, rate);
    MEDIA_LOGI("RateDone %{public}f", rate);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnPlaybackRateDoneCb OH_AVFormat create failed");
    avFormat->format_.PutFloatValue(OH_PLAYER_PLAYBACK_RATE, rate);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_PLAYBACK_RATE_DONE,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnBitRateDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnBitRateDoneCb current source is unready");
    int32_t bitRate = extra;
    MEDIA_LOGI("Bitrate done %{public}d", bitRate);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnBitRateDoneCb OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_BITRATE, bitRate);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_BITRATEDONE, reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnEosCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnEosCb current source is unready");
    int32_t isLooping = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " EOS is called, isloop: %{public}d", FAKE_POINTER(this), isLooping);

    infoCallback_->OnInfo(player_, AV_INFO_TYPE_EOS, nullptr);
}

void NativeAVPlayerCallback::OnStateChangeCb(const int32_t extra, const Format &infoBody)
{
    MEDIA_LOGI("OnStateChangeCb() is called, state %{public}d", extra);
    if (extra == static_cast<int32_t>(PLAYER_RELEASED)) {
        isReleased_.store(true);
    }
    if (player_ == nullptr || infoCallback_ == nullptr) {
        return;
    }
    PlayerStates state = static_cast<PlayerStates>(extra);
    player_->state_ = state;
    for (uint32_t i = 0; i < STATE_MAP_LENGTH; i++) {
        if (STATE_MAP[i].playerStates != state) {
            continue;
        }
        AVPlayerState convertState = STATE_MAP[i].avPlayerState;
        OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
        CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnStateChangeCb OH_AVFormat create failed");

        int32_t reason = StateChangeReason::USER;
        if (infoBody.ContainKey(PlayerKeys::PLAYER_STATE_CHANGED_REASON)) {
            (void)infoBody.GetIntValue(PlayerKeys::PLAYER_STATE_CHANGED_REASON, reason);
        }
        avFormat->format_.PutIntValue(OH_PLAYER_STATE_CHANGE_REASON, static_cast<int32_t>(reason));
        avFormat->format_.PutIntValue(OH_PLAYER_STATE, static_cast<int32_t>(convertState));
        infoCallback_->OnInfo(player_, AV_INFO_TYPE_STATE_CHANGE,
            reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
        return;
    }
}

void NativeAVPlayerCallback::OnPositionUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnPositionUpdateCb current source is unready");
    int32_t position = extra;
    MEDIA_LOGD("OnPositionUpdateCb is called, position: %{public}d", position);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnPositionUpdateCb OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_CURRENT_POSITION, position);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_POSITION_UPDATE,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnVolumeChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnVolumeChangeCb current source is unready");
    float volumeLevel = 0.0;
    (void)infoBody.GetFloatValue(PlayerKeys::PLAYER_VOLUME_LEVEL, volumeLevel);
    MEDIA_LOGD("OnVolumeChangeCb in volume=%{public}f", volumeLevel);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnVolumeChangeCb OH_AVFormat create failed");
    avFormat->format_.PutFloatValue(OH_PLAYER_VOLUME, volumeLevel);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_VOLUME_CHANGE,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnMessageCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnMessageCb current source is unready");
    int32_t messageType = extra;
    MEDIA_LOGI("OnMessageCb is called, extra: %{public}d", messageType);
    if (extra == PlayerMessageType::PLAYER_INFO_VIDEO_RENDERING_START) {
        OnStartRenderFrameCb();
    }
}

void NativeAVPlayerCallback::OnStartRenderFrameCb() const
{
    MEDIA_LOGI("OnStartRenderFrameCb is called");
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnStartRenderFrameCb current source is unready");

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnStartRenderFrameCb OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_MESSAGE_TYPE, 1); // 1 means PLAYER_INFO_VIDEO_RENDERING_START
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_MESSAGE, reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnVideoSizeChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnVideoSizeChangedCb current source is unready");
    int32_t width = 0;
    int32_t height = 0;
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_WIDTH, width);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_HEIGHT, height);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " sizeChange w %{public}d h %{public}d", FAKE_POINTER(this), width, height);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnVideoSizeChangedCb OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_VIDEO_WIDTH, width);
    avFormat->format_.PutIntValue(OH_PLAYER_VIDEO_HEIGHT, height);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_RESOLUTION_CHANGE,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnBufferingUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnBufferingUpdateCb current source is unready");
    int32_t val = 0;
    AVPlayerBufferingType bufferingType;
    if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_START))) {
        bufferingType = AVPlayerBufferingType::AVPLAYER_BUFFERING_START;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_START), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_END))) {
        bufferingType = AVPlayerBufferingType::AVPLAYER_BUFFERING_END;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_END), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_PERCENT))) {
        bufferingType = AVPlayerBufferingType::AVPLAYER_BUFFERING_PERCENT;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_PERCENT), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_CACHED_DURATION))) {
        bufferingType = AVPlayerBufferingType::AVPLAYER_BUFFERING_CACHED_DURATION;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_CACHED_DURATION), val);
    } else {
        return;
    }
    MEDIA_LOGD("OnBufferingUpdateCb is called, buffering type: %{public}d value: %{public}d",
        static_cast<int32_t>(bufferingType), val);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnBufferingUpdateCb OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_BUFFERING_TYPE, static_cast<int32_t>(bufferingType));
    avFormat->format_.PutIntValue(OH_PLAYER_BUFFERING_VALUE, val);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_BUFFERING_UPDATE,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnBitRateCollectedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnBitRateCollectedCb current source is unready");

    uint8_t *addr = nullptr;
    size_t size  = 0;
    if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_AVAILABLE_BITRATES))) {
        infoBody.GetBuffer(std::string(PlayerKeys::PLAYER_AVAILABLE_BITRATES), &addr, size);
    }
    CHECK_AND_RETURN_LOG(addr != nullptr, "bitRates addr is nullptr");
    size_t bitRatesCount = static_cast<size_t>(size / sizeof(uint32_t));
    CHECK_AND_RETURN_LOG(bitRatesCount > 0, "bitRates size(%{public}zu) is invalid", size);
    MEDIA_LOGI("bitRates count: %{public}zu", bitRatesCount);
    for (size_t i = 0; i < bitRatesCount; i++) {
        MEDIA_LOGI("bitRates[%{public}zu]: %{public}u", i, *(static_cast<uint32_t*>(static_cast<void*>(addr)) + i));
    }

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnBitRateCollectedCb OH_AVFormat create failed");
    avFormat->format_.PutBuffer(OH_PLAYER_BITRATE_ARRAY, addr, static_cast<size_t>(bitRatesCount * sizeof(uint32_t)));
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_BITRATE_COLLECT,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnAudioInterruptCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnAudioInterruptCb current source is unready");
    int32_t eventType = 0;
    int32_t forceType = 0;
    int32_t hintType = 0;
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_TYPE, eventType);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_FORCE, forceType);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_HINT, hintType);
    MEDIA_LOGI("OnAudioInterruptCb is called, eventType: %{public}d, forceType: %{public}d, hintType: %{public}d",
        eventType, forceType, hintType);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnAudioInterruptCb OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_AUDIO_INTERRUPT_TYPE, eventType);
    avFormat->format_.PutIntValue(OH_PLAYER_AUDIO_INTERRUPT_FORCE, forceType);
    avFormat->format_.PutIntValue(OH_PLAYER_AUDIO_INTERRUPT_HINT, hintType);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_INTERRUPT_EVENT,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnDurationUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnDurationUpdateCb current source is unready");
    int64_t duration = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " duration update %{public}" PRId64, FAKE_POINTER(this), duration);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnDurationUpdateCb OH_AVFormat create failed");
    avFormat->format_.PutLongValue(OH_PLAYER_DURATION, duration);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_DURATION_UPDATE,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnNotifyIsLiveStream(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    (void)infoBody;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnNotifyIsLiveStream extra: %{public}d", FAKE_POINTER(this), extra);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnNotifyIsLiveStream OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_IS_LIVE_STREAM, 1); // 1 means is live stream
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_IS_LIVE_STREAM,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnTrackChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    int32_t trackIndex = -1;
    int32_t isSelect = -1;
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_TRACK_INDEX), trackIndex);
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_IS_SELECT), isSelect);
    MEDIA_LOGI("OnTrackChangedCb trackIndex: %{public}d, isSelect: %{public}d", trackIndex, isSelect);
    CHECK_AND_RETURN_LOG(trackIndex != -1 && isSelect != -1, "invalid trackIndex: %{public}d, isSelect: %{public}d",
        trackIndex, isSelect);
    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnTrackChangedCb OH_AVFormat create failed");
    avFormat->format_.PutIntValue(OH_PLAYER_TRACK_INDEX, trackIndex);
    avFormat->format_.PutIntValue(OH_PLAYER_TRACK_IS_SELECT, isSelect);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_TRACKCHANGE, reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnTrackInfoUpdate(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    (void)extra;
    MEDIA_LOGI("OnTrackInfoUpdate not support");
}

void NativeAVPlayerCallback::OnSubtitleInfoCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    int32_t pts = -1;
    int32_t duration = -1;
    std::string text;
    infoBody.GetStringValue(PlayerKeys::SUBTITLE_TEXT, text);
    infoBody.GetIntValue(std::string(PlayerKeys::SUBTITLE_PTS), pts);
    infoBody.GetIntValue(std::string(PlayerKeys::SUBTITLE_DURATION), duration);
    MEDIA_LOGI("OnSubtitleInfoCb pts: %{public}d, duration: %{public}d", pts, duration);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnSubtitleInfoCb OH_AVFormat create failed");
    avFormat->format_.PutStringValue(OH_PLAYER_SUBTITLE_TEXT, text);
    avFormat->format_.PutIntValue(OH_PLAYER_SUBTITLE_PTS, pts);
    avFormat->format_.PutIntValue(OH_PLAYER_SUBTITLE_DURATION, duration);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_SUBTITLE_UPDATE,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnAudioDeviceChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isSourceLoaded_.load(), "OnAudioDeviceChangeCb current source is unready");

    int32_t reason = 0; // means UNKOWN, see OH_AudioStream_DeviceChangeReason
    infoBody.GetIntValue(PlayerKeys::AUDIO_DEVICE_CHANGE_REASON, reason);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnAudioDeviceChangeCb reason: %{public}d", FAKE_POINTER(this), reason);

    OHOS::sptr<OH_AVFormat> avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_LOG(avFormat != nullptr, "OnAudioDeviceChangeCb OH_AVFormat create failed");
    // We only report AUDIO_DEVICE_CHANGE_REASON at this stage.
    avFormat->format_.PutIntValue(OH_PLAYER_AUDIO_DEVICE_CHANGE_REASON, reason);
    infoCallback_->OnInfo(player_, AV_INFO_TYPE_AUDIO_OUTPUT_DEVICE_CHANGE,
        reinterpret_cast<OH_AVFormat *>(avFormat.GetRefPtr()));
}

void NativeAVPlayerCallback::OnDrmInfoUpdatedCb(const int32_t extra, const Format &infoBody)
{
#ifdef SUPPORT_AVPLAYER_DRM
    if (drmsysteminfocallback_ == nullptr) {
        return;
    }
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player_);
    DRM_MediaKeySystemInfo mediaKeySystemInfo;
    GetDrmSystemInfos(infoBody, &mediaKeySystemInfo, playerObj);
    drmsysteminfocallback_(player_, &mediaKeySystemInfo);
#else
    (void)drmsysteminfocallback_;
    (void)extra;
    (void)infoBody;
#endif
}

OH_AVPlayer *OH_AVPlayer_Create(void)
{
    std::shared_ptr<Player> player = PlayerFactory::CreatePlayer(OHOS::Media::PlayerProducer::CAPI);
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "failed to PlayerFactory::CreatePlayer");

    PlayerObject *object = new(std::nothrow) PlayerObject(player);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to new PlayerObject");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OH_AVPlayer_Create", FAKE_POINTER(object));

    return object;
}

OH_AVErrCode OH_AVPlayer_SetURLSource(OH_AVPlayer *player, const char *url)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    CHECK_AND_RETURN_RET_LOG(url != nullptr, AV_ERR_INVALID_VAL, "url is null");
    playerObj->StartListenCurrentResource();
    int32_t ret = playerObj->player_->SetSource(url);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player setUrlSource failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetFDSource(OH_AVPlayer *player, int32_t fd, int64_t offset, int64_t size)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    CHECK_AND_RETURN_RET_LOG(fd >= 0, AV_ERR_INVALID_VAL, "fd is invalid");
    playerObj->StartListenCurrentResource();
    int32_t ret = playerObj->player_->SetSource(fd, offset, size);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player setFdSource failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_Prepare(OH_AVPlayer *player)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->PrepareAsync();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player Prepare failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_Play(OH_AVPlayer *player)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->Play();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player play failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_Pause(OH_AVPlayer *player)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->Pause();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player Pause failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_Stop(OH_AVPlayer *player)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->Stop();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player Stop failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_Reset(OH_AVPlayer *player)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    playerObj->PauseListenCurrentResource(); // Pause event listening for the current resource
    int32_t ret = playerObj->player_->Reset();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player Reset failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_Release(OH_AVPlayer *player)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    CHECK_AND_RETURN_RET_LOG(!playerObj->isReleased_.load(), AV_ERR_OK, "player alreay isReleased");
    playerObj->PauseListenCurrentResource(); // Pause event listening for the current resource
    int32_t ret = playerObj->player_->Release();
    playerObj->isReleased_.store(true);
    if (playerObj->callback_ != nullptr) {
        Format format;
        playerObj->callback_->OnInfo(INFO_TYPE_STATE_CHANGE, PLAYER_RELEASED, format);
    }
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player Release failed");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OH_AVPlayer_Release", FAKE_POINTER(playerObj));
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_ReleaseSync(OH_AVPlayer *player)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    CHECK_AND_RETURN_RET_LOG(!playerObj->isReleased_.load(), AV_ERR_OK, "player alreay isReleased");
    playerObj->PauseListenCurrentResource(); // Pause event listening for the current resource
    int32_t ret = playerObj->player_->ReleaseSync();
    playerObj->isReleased_.store(true);
    if (playerObj->callback_ != nullptr) {
        Format format;
        playerObj->callback_->OnInfo(INFO_TYPE_STATE_CHANGE, PLAYER_RELEASED, format);
    }
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player ReleaseSync failed");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OH_AVPlayer_ReleaseSync", FAKE_POINTER(playerObj));
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetVolume(OH_AVPlayer *player, float leftVolume, float rightVolume)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->SetVolume(leftVolume, rightVolume);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetVolume failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetVolumeMode(OH_AVPlayer *player, OH_AudioStream_VolumeMode mode)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->SetVolumeMode(static_cast<int32_t>(mode));
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetVolumeMode failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_Seek(OH_AVPlayer *player, int32_t mSeconds, AVPlayerSeekMode mode)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    PlayerSeekMode seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
    switch (mode) {
        case AVPlayerSeekMode::AV_SEEK_NEXT_SYNC:
            seekMode = PlayerSeekMode::SEEK_NEXT_SYNC;
            break;
        case AVPlayerSeekMode::AV_SEEK_PREVIOUS_SYNC:
            seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
            break;
        case AVPlayerSeekMode::AV_SEEK_CLOSEST:
            seekMode = PlayerSeekMode::SEEK_CLOSEST;
            break;
        default:
            seekMode = PlayerSeekMode::SEEK_PREVIOUS_SYNC;
            break;
    }
    int32_t ret = playerObj->player_->Seek(mSeconds, seekMode);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player Seek failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_GetCurrentTime(OH_AVPlayer *player, int32_t *currentTime)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(currentTime != nullptr, AV_ERR_INVALID_VAL, "currentTime is nullptr");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->GetCurrentTime(*currentTime);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player GetCurrentTime failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_GetVideoWidth(OH_AVPlayer *player, int32_t *videoWidth)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(videoWidth != nullptr, AV_ERR_INVALID_VAL, "videoWidth is nullptr");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    *videoWidth = playerObj->player_->GetVideoWidth();
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_GetVideoHeight(OH_AVPlayer *player, int32_t *videoHeight)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(videoHeight != nullptr, AV_ERR_INVALID_VAL, "videoHeight is nullptr");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    *videoHeight = playerObj->player_->GetVideoHeight();
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetPlaybackSpeed(OH_AVPlayer *player, AVPlaybackSpeed speed)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->SetPlaybackSpeed(static_cast<PlaybackRateMode>(speed));
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetPlaybackSpeed failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetPlaybackRate(OH_AVPlayer *player, float rate)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->SetPlaybackRate(rate);
    if (ret == MSERR_OK) {
        return AV_ERR_OK;
    } else if (ret == MSERR_INVALID_OPERATION || ret == MSERR_SERVICE_DIED) {
        return AV_ERR_OPERATE_NOT_PERMIT;
    }
    return AV_ERR_INVALID_VAL;
}

OH_AVErrCode OH_AVPlayer_GetPlaybackSpeed(OH_AVPlayer *player, AVPlaybackSpeed *speed)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(speed != nullptr, AV_ERR_INVALID_VAL, "speed is nullptr");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    PlaybackRateMode md;
    int32_t ret = playerObj->player_->GetPlaybackSpeed(md);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player GetPlaybackSpeed failed");
    *speed = static_cast<AVPlaybackSpeed>(md);
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetAudioRendererInfo(OH_AVPlayer *player, OH_AudioStream_Usage streamUsage)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    if (streamUsage < OH_AudioStream_Usage::AUDIOSTREAM_USAGE_UNKNOWN ||
        streamUsage > OH_AudioStream_Usage::AUDIOSTREAM_USAGE_NAVIGATION) {
        return AV_ERR_INVALID_VAL;
    }
    Format format;
    (void)format.PutIntValue(PlayerKeys::STREAM_USAGE, streamUsage);
    (void)format.PutIntValue(PlayerKeys::CONTENT_TYPE, 0);
    (void)format.PutIntValue(PlayerKeys::RENDERER_FLAG, 0);
    int32_t ret = playerObj->player_->SetParameter(format);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetAudioRendererInfo failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetAudioInterruptMode(OH_AVPlayer *player, OH_AudioInterrupt_Mode interruptMode)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    if (interruptMode < OH_AudioInterrupt_Mode::AUDIOSTREAM_INTERRUPT_MODE_SHARE ||
        interruptMode > OH_AudioInterrupt_Mode::AUDIOSTREAM_INTERRUPT_MODE_INDEPENDENT) {
        return AV_ERR_INVALID_VAL;
    }
    Format format;
    (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, interruptMode);
    int32_t ret = playerObj->player_->SetParameter(format);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetAudioInterruptMode failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetAudioEffectMode(OH_AVPlayer *player, OH_AudioStream_AudioEffectMode effectMode)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    if (effectMode < OH_AudioStream_AudioEffectMode::EFFECT_NONE ||
        effectMode > OH_AudioStream_AudioEffectMode::EFFECT_DEFAULT) {
        return AV_ERR_INVALID_VAL;
    }
    Format format;
    (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, effectMode);
    int32_t ret = playerObj->player_->SetParameter(format);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetAudioEffectMode failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SelectBitRate(OH_AVPlayer *player, uint32_t bitRate)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->SelectBitRate(bitRate);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SelectBitRate failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_GetDuration(OH_AVPlayer *player, int32_t *duration)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(duration != nullptr, AV_ERR_INVALID_VAL, "duration is nullptr");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->GetDuration(*duration);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player GetDuration failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_GetState(OH_AVPlayer *player, AVPlayerState *state)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(state != nullptr, AV_ERR_INVALID_VAL, "state is nullptr");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    if (playerObj->isReleased_.load()) {
        *state = AVPlayerState::AV_RELEASED;
        return AV_ERR_OK;
    }
    for (uint32_t i = 0; i < STATE_MAP_LENGTH; i++) {
        if (STATE_MAP[i].playerStates == player->state_) {
            *state = STATE_MAP[i].avPlayerState;
            return AV_ERR_OK;
        }
    }

    *state = AV_ERROR;
    return AV_ERR_OK;
}

#ifdef SUPPORT_VIDEO
OH_AVErrCode  OH_AVPlayer_SetVideoSurface(OH_AVPlayer *player, OHNativeWindow *window)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(window != nullptr, AV_ERR_INVALID_VAL, "Window is nullptr!");
    CHECK_AND_RETURN_RET_LOG(window->surface != nullptr, AV_ERR_INVALID_VAL, "Input window surface is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->SetVideoSurface(window->surface);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "SetVideoSurface failed!");
    return AV_ERR_OK;
}
#endif

bool OH_AVPlayer_IsPlaying(OH_AVPlayer *player)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, false, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, false, "player_ is null");
    return playerObj->player_->IsPlaying();
}

bool OH_AVPlayer_IsLooping(OH_AVPlayer *player)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, false, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, false, "player_ is null");
    return playerObj->player_->IsLooping();
}

OH_AVErrCode OH_AVPlayer_SetLooping(OH_AVPlayer *player, bool loop)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->SetLooping(loop);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetLooping failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetPlayerCallback(OH_AVPlayer *player, AVPlayerCallback callback)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    CHECK_AND_RETURN_RET_LOG(callback.onInfo != nullptr, AV_ERR_INVALID_VAL, "onInfo is null");
    CHECK_AND_RETURN_RET_LOG(callback.onError != nullptr, AV_ERR_INVALID_VAL, "onError is null");
    if (playerObj->callback_ == nullptr) {
        NativeAVPlayerCallback *avplayerCallback =
            new (std::nothrow) NativeAVPlayerCallback(player, callback);
        CHECK_AND_RETURN_RET_LOG(avplayerCallback != nullptr, AV_ERR_NO_MEMORY, "avplayerCallback is nullptr!");
        playerObj->callback_ = std::shared_ptr<NativeAVPlayerCallback>(avplayerCallback);
    } else {
        playerObj->callback_->SetPlayCallback(callback);
    }
    int32_t ret = playerObj->player_->SetPlayerCallback(playerObj->callback_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetPlayerCallback failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SelectTrack(OH_AVPlayer *player, int32_t index)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->SelectTrack(index);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SelectTrack failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_DeselectTrack(OH_AVPlayer *player, int32_t index)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->DeselectTrack(index);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player DeselectTrack failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_GetCurrentTrack(OH_AVPlayer *player, int32_t trackType, int32_t *index)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(index != nullptr, AV_ERR_INVALID_VAL, "index is nullptr");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->GetCurrentTrack(trackType, *index);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player GetCurrentTrack failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetMediaKeySystemInfoCallback(OH_AVPlayer *player,
    Player_MediaKeySystemInfoCallback callback)
{
#ifdef SUPPORT_AVPLAYER_DRM
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "MediaKeySystemInfoCallback is null");
    
    if (playerObj->callback_ == nullptr) {
        static AVPlayerCallback playCallback = { nullptr, nullptr };
        playerObj->callback_ = std::make_shared<NativeAVPlayerCallback>(player, playCallback);
        int32_t ret = playerObj->player_->SetPlayerCallback(playerObj->callback_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetDrmSystemInfoCallback failed");
        ret = playerObj->callback_->SetDrmSystemInfoCallback(callback);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetDrmSystemInfoCallback failed");
    } else {
        int32_t ret = playerObj->callback_->SetDrmSystemInfoCallback(callback);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetDrmSystemInfoCallback failed");
    }
#else
    (void)player;
    (void)callback;
#endif
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_GetMediaKeySystemInfo(OH_AVPlayer *player, DRM_MediaKeySystemInfo *mediaKeySystemInfo)
{
#ifdef SUPPORT_AVPLAYER_DRM
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaKeySystemInfo != nullptr, AV_ERR_INVALID_VAL, "mediaKeySystemInfo is nullptr");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    CHECK_AND_RETURN_RET_LOG(!playerObj->localDrmInfos_.empty(), AV_ERR_INVALID_VAL, "localDrmInfos_ is null");
    mediaKeySystemInfo->psshCount = playerObj->localDrmInfos_.size();
    int index = 0;
    for (auto item : playerObj->localDrmInfos_) {
        int ret = memcpy_s(mediaKeySystemInfo->psshInfo[index].uuid, item.first.size(),
            item.first.data(), item.first.size());
        CHECK_AND_RETURN_RET_LOG(ret ==0, AV_ERR_INVALID_VAL, "no memory");
        ret = memcpy_s(mediaKeySystemInfo->psshInfo[index].data, item.second.size(),
            item.second.data(), item.second.size());
        CHECK_AND_RETURN_RET_LOG(ret ==0, AV_ERR_INVALID_VAL, "no memory");
        mediaKeySystemInfo->psshInfo[index++].dataLen = static_cast<int32_t>(item.second.size());
    }
#else
    (void)player;
    (void)mediaKeySystemInfo;
#endif
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetDecryptionConfig(OH_AVPlayer *player, MediaKeySession *mediaKeySession,
    bool secureVideoPath)
{
#ifdef SUPPORT_AVPLAYER_DRM
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mediaKeySession != nullptr, AV_ERR_INVALID_VAL, "mediaKeySession is nullptr");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    struct MediaKeySessionObject *sessionObject = reinterpret_cast<MediaKeySessionObject *>(mediaKeySession);
    CHECK_AND_RETURN_RET_LOG(sessionObject != nullptr, AV_ERR_INVALID_VAL, "sessionObject is null");
    CHECK_AND_RETURN_RET_LOG(sessionObject->sessionImpl_ != nullptr, AV_ERR_INVALID_VAL, "sessionObject is null");
    int32_t ret =
        playerObj->player_->SetDecryptConfig(sessionObject->sessionImpl_->GetMediaKeySessionServiceProxy(),
            secureVideoPath);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player SetDecryptConfig failed");
#else
    (void)player;
    (void)mediaKeySession;
    (void)secureVideoPath;
#endif
    return AV_ERR_OK;
}

static OH_AVErrCode AVPlayerSetPlayerCallback(OH_AVPlayer *player, struct PlayerObject *playerObj, bool isUnregister)
{
    MEDIA_LOGD("AVPlayerSetPlayerCallback S");
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    CHECK_AND_RETURN_RET_LOG(playerObj != nullptr && playerObj->player_ != nullptr, AV_ERR_INVALID_VAL,
        "player_ is nullptr!");
    if (!isUnregister && playerObj->callback_ == nullptr) {
        MEDIA_LOGI("AVPlayerSetPlayerCallback create dummy NativeAVPlayerCallback");
        AVPlayerCallback dummyCallback = {
            .onInfo = nullptr,
            .onError = nullptr
        };
        NativeAVPlayerCallback *avplayerCallback =
            new (std::nothrow) NativeAVPlayerCallback(player, dummyCallback);
        CHECK_AND_RETURN_RET_LOG(avplayerCallback != nullptr, AV_ERR_NO_MEMORY, "avplayerCallback is nullptr!");
        playerObj->callback_ = std::shared_ptr<NativeAVPlayerCallback>(avplayerCallback);

        int32_t ret = playerObj->player_->SetPlayerCallback(playerObj->callback_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "AVPlayerSetPlayerCallback failed!");
    }
    MEDIA_LOGD("AVPlayerSetPlayerCallback E");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetOnErrorCallback(OH_AVPlayer *player, OH_AVPlayerOnErrorCallback callback, void *userData)
{
    MEDIA_LOGD("OH_AVPlayer_SetOnErrorCallback S");
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "SetOnError input player is nullptr!");
    if (callback == nullptr) {
        MEDIA_LOGI("SetOnError callback is nullptr, unregister callback.");
    }
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "SetOnError player_ is nullptr");

    OH_AVErrCode errCode = AVPlayerSetPlayerCallback(player, playerObj, callback == nullptr);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_ERR_OK, errCode, "AVPlayerSetPlayerCallback AVPlayerOnError error");

    if (playerObj->callback_ == nullptr || playerObj->callback_->SetOnErrorCallback(callback, userData) != AV_ERR_OK) {
        MEDIA_LOGE("OH_AVPlayer_SetOnErrorCallback error");
        return AV_ERR_NO_MEMORY;
    }
    MEDIA_LOGD("OH_AVPlayer_SetOnErrorCallback success E");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetOnInfoCallback(OH_AVPlayer *player, OH_AVPlayerOnInfoCallback callback, void *userData)
{
    MEDIA_LOGD("OH_AVPlayer_SetOnInfoCallback S");
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "SetOnInfo input player is nullptr!");
    if (callback == nullptr) {
        MEDIA_LOGI("SetOnInfo callback is nullptr, unregister callback.");
    }
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "SetOnInfo player_ is nullptr");

    OH_AVErrCode errCode = AVPlayerSetPlayerCallback(player, playerObj, callback == nullptr);
    CHECK_AND_RETURN_RET_LOG(errCode == AV_ERR_OK, errCode, "AVPlayerSetPlayerCallback AVPlayerOnInfoCallback error");

    if (playerObj->callback_ == nullptr || playerObj->callback_->SetOnInfoCallback(callback, userData) != AV_ERR_OK) {
        MEDIA_LOGE("OH_AVPlayer_SetOnInfoCallback error");
        return AV_ERR_NO_MEMORY;
    }
    MEDIA_LOGD("OH_AVPlayer_SetOnInfoCallback success E");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetLoudnessGain(OH_AVPlayer *player, float loudnessGain)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    int32_t ret = playerObj->player_->SetLoudnessGain(loudnessGain);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_STATE, "player SetLoudnessGain failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVPlayer_SetDataSource(OH_AVPlayer *player, OH_AVDataSourceExt* datasrc, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(player != nullptr, AV_ERR_INVALID_VAL, "input player is nullptr!");
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, AV_ERR_INVALID_VAL, "player_ is null");
    CHECK_AND_RETURN_RET_LOG(datasrc != nullptr, AV_ERR_INVALID_VAL, "datasrc is null");
    CHECK_AND_RETURN_RET_LOG(datasrc->readAt != nullptr, AV_ERR_INVALID_VAL, "datasrc readAt is null");
    playerObj->StartListenCurrentResource();
    std::shared_ptr<IMediaDataSource> avDataSource = std::make_shared<NativeAVDataSource>(datasrc, userData);
    int32_t ret = playerObj->player_->SetSource(avDataSource);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, AV_ERR_INVALID_VAL, "player setDataSource failed");
    return AV_ERR_OK;
}

OH_AVFormat *OH_AVPlayer_GetMediaDescription(OH_AVPlayer *player)
{
    MEDIA_LOGI("OH_AVPlayer_getMediaDescription S");
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "SetOnInfo input player is nullptr!");

    OHOS::Media::Format format;
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, nullptr, "player_ is null");
    playerObj->player_->GetMediaDescription(format);
    OH_AVFormat *avFormat = OH_AVFormat_Create();
    CHECK_AND_RETURN_RET_LOG(avFormat != nullptr, nullptr, "Format is nullptr!");
    avFormat->format_ = format;
    return avFormat;
}

OH_AVFormat *OH_AVPlayer_GetTrackDescription(OH_AVPlayer *player, uint32_t index)
{
    MEDIA_LOGI("OH_AVPlayer_GetTrackDescription S");
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "SetOnInfo input player is nullptr!");

    OHOS::Media::Format format;
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, nullptr, "player_ is null");
    int32_t ret = playerObj->player_->GetTrackDescription(format, index);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "player GetTrackDescription failed");
    OH_AVFormat *avFormat = OH_AVFormat_Create();
    CHECK_AND_RETURN_RET_LOG(avFormat != nullptr, nullptr, "Format is nullptr!");
    avFormat->format_ = format;
    return avFormat;
}

OH_AVFormat *OH_AVPlayer_GetPlaybackStatisticMetrics(OH_AVPlayer *player)
{
    MEDIA_LOGI("OH_AVPlayer_GetPlaybackStatisticMetrics S");
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "SetOnInfo input player is nullptr!");

    OHOS::Media::Format format;
    struct PlayerObject *playerObj = reinterpret_cast<PlayerObject *>(player);
    CHECK_AND_RETURN_RET_LOG(playerObj->player_ != nullptr, nullptr, "player_ is null");
    int32_t ret = playerObj->player_->GetPlaybackStatisticMetrics(format);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "player GetPlaybackStatisticMetrics failed");
    OH_AVFormat *avFormat = OH_AVFormat_Create();
    CHECK_AND_RETURN_RET_LOG(avFormat != nullptr, nullptr, "Format is nullptr!");
    avFormat->format_ = format;
    return avFormat;
}
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

#include <iomanip>
#include <sstream>
#include "cj_avplayer_callback.h"

#include "media_errors.h"
#include "media_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "CJAVPlayerCallback"};
}

namespace OHOS {
namespace Media {
CJAVPlayerCallback::CJAVPlayerCallback(CJAVPlayerNotify *listener) : listener_(listener)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    onInfoFuncs_ = {
        {INFO_TYPE_STATE_CHANGE,
         [this](const int32_t extra, const Format &infoBody) { OnStateChangeCb(extra, infoBody); }},
        {INFO_TYPE_VOLUME_CHANGE,
         [this](const int32_t extra, const Format &infoBody) { OnVolumeChangeCb(extra, infoBody); }},
        {INFO_TYPE_SEEKDONE, [this](const int32_t extra, const Format &infoBody) { OnSeekDoneCb(extra, infoBody); }},
        {INFO_TYPE_SPEEDDONE, [this](const int32_t extra, const Format &infoBody) { OnSpeedDoneCb(extra, infoBody); }},
        {INFO_TYPE_BITRATEDONE,
         [this](const int32_t extra, const Format &infoBody) { OnBitRateDoneCb(extra, infoBody); }},
        {INFO_TYPE_POSITION_UPDATE,
         [this](const int32_t extra, const Format &infoBody) { OnPositionUpdateCb(extra, infoBody); }},
        {INFO_TYPE_DURATION_UPDATE,
         [this](const int32_t extra, const Format &infoBody) { OnDurationUpdateCb(extra, infoBody); }},
        {INFO_TYPE_BUFFERING_UPDATE,
         [this](const int32_t extra, const Format &infoBody) { OnBufferingUpdateCb(extra, infoBody); }},
        {INFO_TYPE_MESSAGE, [this](const int32_t extra, const Format &infoBody) { OnMessageCb(extra, infoBody); }},
        {INFO_TYPE_RESOLUTION_CHANGE,
         [this](const int32_t extra, const Format &infoBody) { OnVideoSizeChangedCb(extra, infoBody); }},
        {INFO_TYPE_INTERRUPT_EVENT,
         [this](const int32_t extra, const Format &infoBody) { OnAudioInterruptCb(extra, infoBody); }},
        {INFO_TYPE_BITRATE_COLLECT,
         [this](const int32_t extra, const Format &infoBody) { OnBitRateCollectedCb(extra, infoBody); }},
        {INFO_TYPE_EOS, [this](const int32_t extra, const Format &infoBody) { OnEosCb(extra, infoBody); }},
        {INFO_TYPE_TRACKCHANGE,
         [this](const int32_t extra, const Format &infoBody) { OnTrackChangedCb(extra, infoBody); }},
        {INFO_TYPE_TRACK_INFO_UPDATE,
         [this](const int32_t extra, const Format &infoBody) { OnTrackInfoUpdate(extra, infoBody); }},
        {INFO_TYPE_DRM_INFO_UPDATED,
         [this](const int32_t extra, const Format &infoBody) { OnDrmInfoUpdatedCb(extra, infoBody); }},
        {INFO_TYPE_SUBTITLE_UPDATE_INFO,
         [this](const int32_t extra, const Format &infoBody) { OnSubtitleInfoCb(extra, infoBody); }},
        {INFO_TYPE_AUDIO_DEVICE_CHANGE,
         [this](const int32_t extra, const Format &infoBody) { OnAudioDeviceChangeCb(extra, infoBody); }},
        {INFO_TYPE_MAX_AMPLITUDE_COLLECT,
         [this](const int32_t extra, const Format &infoBody) { OnMaxAmplitudeCollectedCb(extra, infoBody); }},
    };
}

void CJAVPlayerCallback::OnAudioDeviceChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (audioDeviceChangeCallback == nullptr) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " can not find audio AudioDeviceChange callback!", FAKE_POINTER(this));
        return;
    }

    uint8_t *parcelBuffer = nullptr;
    size_t parcelSize;
    infoBody.GetBuffer(PlayerKeys::AUDIO_DEVICE_CHANGE, &parcelBuffer, parcelSize);
    Parcel parcel;
    parcel.WriteBuffer(parcelBuffer, parcelSize);
    AudioStandard::AudioDeviceDescriptor deviceInfo(AudioStandard::AudioDeviceDescriptor::DEVICE_INFO);
    deviceInfo.Unmarshalling(parcel);

    int32_t reason;
    infoBody.GetIntValue(PlayerKeys::AUDIO_DEVICE_CHANGE_REASON, reason);

    audioDeviceChangeCallback(deviceInfo, reason);
}

CJAVPlayerCallback::~CJAVPlayerCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void CJAVPlayerCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MediaServiceExtErrCodeAPI9 errorCodeApi9 = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errorCode));
    if (errorCodeApi9 == MSERR_EXT_API9_NO_PERMISSION || errorCodeApi9 == MSERR_EXT_API9_NO_MEMORY ||
        errorCodeApi9 == MSERR_EXT_API9_TIMEOUT || errorCodeApi9 == MSERR_EXT_API9_SERVICE_DIED ||
        errorCodeApi9 == MSERR_EXT_API9_UNSUPPORT_FORMAT) {
        Format infoBody;
        CJAVPlayerCallback::OnInfo(INFO_TYPE_STATE_CHANGE, PLAYER_STATE_ERROR, infoBody);
    }
    CJAVPlayerCallback::OnErrorCb(errorCodeApi9, errorMsg);
}

void CJAVPlayerCallback::OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    std::string message = MSExtAVErrorToString(errorCode) + errorMsg;
    MEDIA_LOGE("OnErrorCb:errorCode %{public}d, errorMsg %{public}s", errorCode, message.c_str());
    if (errorCallback == nullptr) {
        MEDIA_LOGW("0x%{public}06" PRIXPTR " can not find error callback!", FAKE_POINTER(this));
        return;
    }
    errorCallback(errorCode, errorMsg);
}

void CJAVPlayerCallback::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGD("OnInfo is called, PlayerOnInfoType: %{public}d", type);
    if (onInfoFuncs_.count(type) > 0) {
        onInfoFuncs_[type](extra, infoBody);
    } else {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " OnInfo: no member func supporting, %{public}d", FAKE_POINTER(this), type);
    }
}

bool CJAVPlayerCallback::IsValidState(PlayerStates state, std::string &stateStr)
{
    switch (state) {
        case PlayerStates::PLAYER_IDLE:
            stateStr = AVPlayerState::STATE_IDLE;
            break;
        case PlayerStates::PLAYER_INITIALIZED:
            stateStr = AVPlayerState::STATE_INITIALIZED;
            break;
        case PlayerStates::PLAYER_PREPARED:
            stateStr = AVPlayerState::STATE_PREPARED;
            break;
        case PlayerStates::PLAYER_STARTED:
            stateStr = AVPlayerState::STATE_PLAYING;
            break;
        case PlayerStates::PLAYER_PAUSED:
            stateStr = AVPlayerState::STATE_PAUSED;
            break;
        case PlayerStates::PLAYER_STOPPED:
            stateStr = AVPlayerState::STATE_STOPPED;
            break;
        case PlayerStates::PLAYER_PLAYBACK_COMPLETE:
            stateStr = AVPlayerState::STATE_COMPLETED;
            break;
        case PlayerStates::PLAYER_RELEASED:
            stateStr = AVPlayerState::STATE_RELEASED;
            break;
        case PlayerStates::PLAYER_STATE_ERROR:
            stateStr = AVPlayerState::STATE_ERROR;
            break;
        default:
            return false;
    }
    return true;
}

void CJAVPlayerCallback::OnStateChangeCb(const int32_t extra, const Format &infoBody)
{
    PlayerStates state = static_cast<PlayerStates>(extra);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instance OnStateChanged is called, current state: %{public}d",
               FAKE_POINTER(this), state);

    if (listener_ != nullptr) {
        listener_->NotifyState(state);
    }

    if (state_ != state) {
        state_ = state;
        std::string stateStr;
        if (IsValidState(state, stateStr)) {
            if (stateChangeCallback == nullptr) {
                MEDIA_LOGW("can not find state change callback!");
                return;
            }

            int32_t reason = StateChangeReason::USER;
            if (infoBody.ContainKey(PlayerKeys::PLAYER_STATE_CHANGED_REASON)) {
                (void)infoBody.GetIntValue(PlayerKeys::PLAYER_STATE_CHANGED_REASON, reason);
            }
            stateChangeCallback(stateStr, reason);
        }
    }
}

void CJAVPlayerCallback::OnVolumeChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    float volumeLevel = 0.0;
    (void)infoBody.GetFloatValue(PlayerKeys::PLAYER_VOLUME_LEVEL, volumeLevel);

    isSetVolume_ = false;
    MEDIA_LOGD("OnVolumeChangeCb in volume=%{public}f", volumeLevel);
    if (volumeChangeCallback == nullptr) {
        MEDIA_LOGD("can not find vol change callback!");
        return;
    }
    volumeChangeCallback(volumeLevel);
}

void CJAVPlayerCallback::OnSeekDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t currentPositon = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnSeekDone is called, currentPositon: %{public}d", FAKE_POINTER(this),
               currentPositon);
    if (seekDoneCallback == nullptr) {
        MEDIA_LOGW("0x%{public}06" PRIXPTR " can not find seekdone callback!", FAKE_POINTER(this));
        return;
    }
    seekDoneCallback(currentPositon);
}

void CJAVPlayerCallback::OnSpeedDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t speedMode = extra;
    MEDIA_LOGI("OnSpeedDoneCb is called, speedMode: %{public}d", speedMode);
    if (speedDoneCallback == nullptr) {
        MEDIA_LOGW("can not find speeddone callback!");
        return;
    }
    speedDoneCallback(speedMode);
}

void CJAVPlayerCallback::OnBitRateDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t bitRate = extra;
    MEDIA_LOGI("OnBitRateDoneCb is called, bitRate: %{public}d", bitRate);
    if (bitRateDoneCallback == nullptr) {
        MEDIA_LOGW("can not find bitrate callback!");
        return;
    }
    bitRateDoneCallback(bitRate);
}

void CJAVPlayerCallback::OnPositionUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t position = extra;
    MEDIA_LOGD("OnPositionUpdateCb is called, position: %{public}d", position);

    if (listener_ != nullptr) {
        listener_->NotifyPosition(position);
    }

    if (timeUpdateCallback == nullptr) {
        MEDIA_LOGD("can not find timeupdate callback!");
        return;
    }
    timeUpdateCallback(position);
}

void CJAVPlayerCallback::OnDurationUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t duration = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnDurationUpdateCb is called, duration: %{public}d", FAKE_POINTER(this),
               duration);

    if (listener_ != nullptr) {
        listener_->NotifyDuration(duration);
    }

    if (durationUpdateCallback == nullptr) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " can not find duration update callback!", FAKE_POINTER(this));
        return;
    }
    durationUpdateCallback(duration);
}

void CJAVPlayerCallback::OnBufferingUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (bufferingUpdateCallback == nullptr) {
        MEDIA_LOGD("can not find buffering update callback!");
        return;
    }

    int32_t val = 0;
    int32_t bufferingType = -1;
    if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_START))) {
        bufferingType = BUFFERING_START;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_START), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_END))) {
        bufferingType = BUFFERING_END;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_END), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_PERCENT))) {
        bufferingType = BUFFERING_PERCENT;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_PERCENT), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_CACHED_DURATION))) {
        bufferingType = CACHED_DURATION;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_CACHED_DURATION), val);
    } else {
        return;
    }
    bufferingUpdateCallback(bufferingType, val);
}

void CJAVPlayerCallback::OnMessageCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    MEDIA_LOGI("OnMessageCb is called, extra: %{public}d", extra);
    if (extra == PlayerMessageType::PLAYER_INFO_VIDEO_RENDERING_START) {
        CJAVPlayerCallback::OnStartRenderFrameCb();
    }
}

void CJAVPlayerCallback::OnStartRenderFrameCb() const
{
    MEDIA_LOGI("OnStartRenderFrameCb is called");
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (startRenderFrameCallback == nullptr) {
        MEDIA_LOGW("can not find start render callback!");
        return;
    }
    startRenderFrameCallback();
}

void CJAVPlayerCallback::OnVideoSizeChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t width = 0;
    int32_t height = 0;
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_WIDTH, width);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_HEIGHT, height);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnVideoSizeChangedCb is called, width = %{public}d, height = %{public}d",
               FAKE_POINTER(this), width, height);

    if (listener_ != nullptr) {
        listener_->NotifyVideoSize(width, height);
    }

    if (videoSizeChangeCallback == nullptr) {
        MEDIA_LOGW("can not find video size changed callback!");
        return;
    }
    videoSizeChangeCallback(width, height);
}

void CJAVPlayerCallback::OnAudioInterruptCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (audioInterruptCallback == nullptr) {
        MEDIA_LOGW("can not find audio interrupt callback!");
        return;
    }
    int32_t eventType = 0;
    int32_t forceType = 0;
    int32_t hintType = 0;
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_TYPE, eventType);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_FORCE, forceType);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_HINT, hintType);
    MEDIA_LOGI("OnAudioInterruptCb is called, eventType = %{public}d, forceType = %{public}d, hintType = %{public}d",
               eventType, forceType, hintType);
    audioInterruptCallback(eventType, forceType, hintType);
}

void CJAVPlayerCallback::OnBitRateCollectedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (availableBitratesCallback == nullptr) {
        MEDIA_LOGW("can not find bitrate collected callback!");
        return;
    }

    std::vector<int32_t> bitrateVec;
    if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_AVAILABLE_BITRATES))) {
        uint8_t *addr = nullptr;
        size_t size = 0;
        infoBody.GetBuffer(std::string(PlayerKeys::PLAYER_AVAILABLE_BITRATES), &addr, size);
        CHECK_AND_RETURN_LOG(addr != nullptr, "bitrate addr is nullptr");

        MEDIA_LOGI("bitrate size = %{public}zu", size / sizeof(uint32_t));
        while (size > 0) {
            if (size < sizeof(uint32_t)) {
                break;
            }

            uint32_t bitrate = *(static_cast<uint32_t *>(static_cast<void *>(addr)));
            MEDIA_LOGI("bitrate = %{public}u", bitrate);
            addr += sizeof(uint32_t);
            size -= sizeof(uint32_t);
            bitrateVec.push_back(static_cast<int32_t>(bitrate));
        }
    }
    availableBitratesCallback(bitrateVec);
}

void CJAVPlayerCallback::OnMaxAmplitudeCollectedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (amplitudeUpdateCallback == nullptr) {
        MEDIA_LOGD("can not find max amplitude collected callback!");
        return;
    }

    std::vector<float> MaxAmplitudeVec;
    if (infoBody.ContainKey(std::string(PlayerKeys::AUDIO_MAX_AMPLITUDE))) {
        uint8_t *addr = nullptr;
        size_t size = 0;
        infoBody.GetBuffer(std::string(PlayerKeys::AUDIO_MAX_AMPLITUDE), &addr, size);
        CHECK_AND_RETURN_LOG(addr != nullptr, "max amplitude addr is nullptr");

        MEDIA_LOGD("max amplitude size = %{public}zu", size / sizeof(float));
        while (size > 0) {
            if (size < sizeof(float)) {
                break;
            }

            float maxAmplitude = *(static_cast<float *>(static_cast<void *>(addr)));
            MEDIA_LOGD("maxAmplitude = %{public}f", maxAmplitude);
            addr += sizeof(float);
            size -= sizeof(float);
            MaxAmplitudeVec.push_back(static_cast<float>(maxAmplitude));
        }
    }

    amplitudeUpdateCallback(MaxAmplitudeVec);
}

int32_t CJAVPlayerCallback::SetDrmInfoData(const uint8_t *drmInfoAddr, int32_t infoCount,
                                           std::multimap<std::string, std::vector<uint8_t>> &drmInfoMap)
{
    DrmInfoItem *drmInfos = reinterpret_cast<DrmInfoItem *>(const_cast<uint8_t *>(drmInfoAddr));
    CHECK_AND_RETURN_RET_LOG(drmInfos != nullptr, MSERR_INVALID_VAL, "cast drmInfos nullptr");
    for (int32_t i = 0; i < infoCount; i++) {
        DrmInfoItem temp = drmInfos[i];
        std::stringstream ssConverter;
        std::string uuid;
        for (uint32_t index = 0; index < DrmConstant::DRM_MAX_M3U8_DRM_UUID_LEN; index++) {
            int32_t singleUuid = static_cast<int32_t>(temp.uuid[index]);
            ssConverter << std::hex << std::setfill('0') << std::setw(2) << singleUuid; // 2:w
            uuid = ssConverter.str();
        }
        std::vector<uint8_t> pssh(temp.pssh, temp.pssh + temp.psshLen);
        drmInfoMap.insert({uuid, pssh});
    }

    if (listener_ != nullptr) {
        listener_->NotifyDrmInfoUpdated(drmInfoMap);
    }
    return MSERR_OK;
}

CMediaKeySystemInfo Convert2CMediaKeySystemInfo(std::string uuid, std::vector<uint8_t> pssh)
{
    CMediaKeySystemInfo result = CMediaKeySystemInfo{0};
    result.uuid = MallocCString(uuid);
    if (pssh.size() == 0) {
        return result;
    }
    uint8_t *head = static_cast<uint8_t *>(malloc(sizeof(uint8_t) * pssh.size()));
    if (head == nullptr) {
        return result;
    }
    for (size_t i = 0; i < pssh.size(); i++) {
        head[i] = pssh[i];
    }
    result.pssh = CArrUI8{.head = head, .size = pssh.size()};
    return result;
}

CArrCMediaKeySystemInfo Convert2CArrCMediaKeySystemInfo(const std::multimap<std::string,
    std::vector<uint8_t>> drmInfoMap)
{
    if (drmInfoMap.size() == 0) {
        return CArrCMediaKeySystemInfo{0};
    }
    CMediaKeySystemInfo *head =
        static_cast<CMediaKeySystemInfo *>(malloc(sizeof(CMediaKeySystemInfo) * drmInfoMap.size()));
    if (head == nullptr) {
        return CArrCMediaKeySystemInfo{0};
    }
    int64_t index = 0;
    for (auto iter = drmInfoMap.begin(); iter != drmInfoMap.end(); iter++) {
        head[index] = Convert2CMediaKeySystemInfo(iter->first, iter->second);
        index++;
    }
    return CArrCMediaKeySystemInfo{.head = head, .size = drmInfoMap.size()};
}

void CJAVPlayerCallback::OnDrmInfoUpdatedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    MEDIA_LOGI("CJAVPlayerCallback OnDrmInfoUpdatedCb is called");
    if (mediaKeySystemInfoUpdateCallback == nullptr) {
        MEDIA_LOGW("can not find drm info updated callback!");
        return;
    }
    if (!infoBody.ContainKey(std::string(PlayerKeys::PLAYER_DRM_INFO_ADDR))) {
        MEDIA_LOGW("there's no drminfo-update drm_info_addr key");
        return;
    }
    if (!infoBody.ContainKey(std::string(PlayerKeys::PLAYER_DRM_INFO_COUNT))) {
        MEDIA_LOGW("there's no drminfo-update drm_info_count key");
        return;
    }

    uint8_t *drmInfoAddr = nullptr;
    size_t size = 0;
    int32_t infoCount = 0;
    infoBody.GetBuffer(std::string(PlayerKeys::PLAYER_DRM_INFO_ADDR), &drmInfoAddr, size);
    CHECK_AND_RETURN_LOG(drmInfoAddr != nullptr && size > 0, "get drminfo buffer failed");
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_DRM_INFO_COUNT), infoCount);
    CHECK_AND_RETURN_LOG(infoCount > 0, "get drminfo count is illegal");

    std::multimap<std::string, std::vector<uint8_t>> drmInfoMap;
    int32_t ret = SetDrmInfoData(drmInfoAddr, infoCount, drmInfoMap);
    CHECK_AND_RETURN_LOG(ret == MSERR_OK, "SetDrmInfoData err");
    mediaKeySystemInfoUpdateCallback(Convert2CArrCMediaKeySystemInfo(drmInfoMap));
}

void CJAVPlayerCallback::OnSubtitleInfoCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    int32_t pts = -1;
    int32_t duration = -1;
    std::string text;
    infoBody.GetStringValue(PlayerKeys::SUBTITLE_TEXT, text);
    infoBody.GetIntValue(std::string(PlayerKeys::SUBTITLE_PTS), pts);
    infoBody.GetIntValue(std::string(PlayerKeys::SUBTITLE_DURATION), duration);
    MEDIA_LOGI("OnSubtitleInfoCb pts %{public}d, duration = %{public}d", pts, duration);

    CHECK_AND_RETURN_LOG(subtitleUpdateCallback != nullptr, "can not find Subtitle callback!");

    subtitleUpdateCallback(text, pts, duration);
}

void CJAVPlayerCallback::OnEosCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t isLooping = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnEndOfStream is called, isloop: %{public}d", FAKE_POINTER(this), isLooping);
    if (endOfStreamCallback == nullptr) {
        MEDIA_LOGW("0x%{public}06" PRIXPTR " can not find EndOfStream callback!", FAKE_POINTER(this));
        return;
    }
    endOfStreamCallback();
}

void CJAVPlayerCallback::OnTrackChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    int32_t index = -1;
    int32_t isSelect = -1;
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_TRACK_INDEX), index);
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_IS_SELECT), isSelect);
    MEDIA_LOGI("OnTrackChangedCb index %{public}d, isSelect = %{public}d", index, isSelect);

    CHECK_AND_RETURN_LOG(trackChangeCallback != nullptr, "can not find trackChange callback!");

    trackChangeCallback(index, isSelect);
}

void CJAVPlayerCallback::OnTrackInfoUpdate(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    std::vector<Format> trackInfo;
    (void)infoBody.GetFormatVector(std::string(PlayerKeys::PLAYER_TRACK_INFO), trackInfo);

    MEDIA_LOGI("OnTrackInfoUpdate callback");

    CHECK_AND_RETURN_LOG(trackInfoUpdateCallback != nullptr, "can not find trackInfoUpdate callback!");

    trackInfoUpdateCallback(Convert2CArrCMediaDescription(trackInfo));
}

void CJAVPlayerCallback::Start()
{
    isloaded_ = true;
}

void CJAVPlayerCallback::Pause()
{
    isloaded_ = false;
}

void CJAVPlayerCallback::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);

    Format infoBody;
    CJAVPlayerCallback::OnStateChangeCb(PlayerStates::PLAYER_RELEASED, infoBody);
    listener_ = nullptr;
}

} // namespace Media
} // namespace OHOS

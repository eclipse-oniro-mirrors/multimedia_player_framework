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

#ifndef FRAMEWORKS_ANI_INCLUDE_MEDIA_AVPLAYER_ANI_H
#define FRAMEWORKS_ANI_INCLUDE_MEDIA_AVPLAYER_ANI_H

#include <ani.h>
#include "avmetadatahelper.h"
#include "ani_avplayer_callback.h"
#include "audio_info.h"
#include "player.h"
#include "media_ani_utils.h"
#include "media_data_source_callback_ani.h"
#include "task_queue.h"

namespace OHOS {
namespace Media {

using TaskRet = std::pair<int32_t, std::string>;

class MediaAniResult {
public:
    virtual ~MediaAniResult() = default;
    virtual ani_status GetAniResult(ani_env *env, ani_object &result) = 0;
};

class MediaAniResultArray : public MediaAniResult {
public:
    explicit MediaAniResultArray(const std::vector<Format> &value)
        : value_(value)
    {
    }
    ~MediaAniResultArray() = default;
    ani_status GetAniResult(ani_env *env, ani_object &result) override;

private:
    std::vector<Format> value_;
};

struct AVPlayerContext {
    AVPlayerContext() = default;
    ~AVPlayerContext() = default;
    void SignError(int32_t code, const std::string &message, bool del = true);
    void CheckTaskResult(bool isTimeLimited = false, uint32_t milliseconds = 0)
    {
        if (asyncTask != nullptr) {
            auto result = isTimeLimited ? asyncTask->GetResultWithTimeLimit(milliseconds) : asyncTask->GetResult();
            if (result.HasResult() && result.Value().first != MSERR_EXT_API9_OK) {
                SignError(result.Value().first, result.Value().second);
            }
        }
    }
    std::shared_ptr<TaskHandler<TaskRet>> asyncTask = nullptr;
    std::vector<Format> trackInfoVec_;
    std::unique_ptr<MediaAniResult> aniResult;
    bool errFlag = false;
    int32_t errCode = 0;
    std::string errMessage = "";
    bool delFlag = true;
};

namespace AVPlayerState {
    const std::string STATE_IDLE = "idle";
    const std::string STATE_INITIALIZED = "initialized";
    const std::string STATE_PREPARED = "prepared";
    const std::string STATE_PLAYING = "playing";
    const std::string STATE_PAUSED = "paused";
    const std::string STATE_STOPPED = "stopped";
    const std::string STATE_RELEASED = "released";
    const std::string STATE_ERROR = "error";
    const std::string STATE_COMPLETED = "completed";
}

namespace AVPlayerEvent {
    const std::string EVENT_STATE_CHANGE = "stateChange";
    const std::string EVENT_VOLUME_CHANGE = "volumeChange";
    const std::string EVENT_END_OF_STREAM = "endOfStream";
    const std::string EVENT_SEEK_DONE = "seekDone";
    const std::string EVENT_SPEED_DONE = "speedDone";
    const std::string EVENT_BITRATE_DONE = "bitrateDone";
    const std::string EVENT_TIME_UPDATE = "timeUpdate";
    const std::string EVENT_DURATION_UPDATE = "durationUpdate";
    const std::string EVENT_SUBTITLE_TEXT_UPDATE = "subtitleTextUpdate";
    const std::string EVENT_BUFFERING_UPDATE = "bufferingUpdate";
    const std::string EVENT_START_RENDER_FRAME = "startRenderFrame";
    const std::string EVENT_VIDEO_SIZE_CHANGE = "videoSizeChange";
    const std::string EVENT_AUDIO_INTERRUPT = "audioInterrupt";
    const std::string EVENT_AVAILABLE_BITRATES = "availableBitrates";
    const std::string EVENT_TRACKCHANGE = "trackChange";
    const std::string EVENT_TRACK_INFO_UPDATE = "trackInfoUpdate";
    const std::string EVENT_DRM_INFO_UPDATE = "mediaKeySystemInfoUpdate";
    const std::string EVENT_SET_DECRYPT_CONFIG_DONE = "setDecryptConfigDone";
    const std::string EVENT_AUDIO_DEVICE_CHANGE = "audioOutputDeviceChangeWithInfo";
    const std::string EVENT_SUBTITLE_UPDATE = "subtitleUpdate";
    const std::string EVENT_ERROR = "error";
    const std::string EVENT_AMPLITUDE_UPDATE = "amplitudeUpdate";
}

class AVPlayerAni : public ANIAVPlayerNotify {
public:
    AVPlayerAni();
    ~AVPlayerAni();
    static ani_status AVPlayerAniInit(ani_env *env);
    static ani_object Constructor([[maybe_unused]] ani_env *env);
    static AVPlayerAni* Unwrapp(ani_env *env, ani_object object);

    void SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void ClearCallbackReference(const std::string &callbackName);
    static void SetDataSrc(ani_env *env, ani_object object, ani_object dataObj);
    static ani_object GetDataSrc(ani_env *env, ani_object object);
    static void SetAudioInterruptMode(ani_env *env, ani_object object, ani_enum_item mode);
    static ani_enum_item GetAudioInterruptMode(ani_env *env, ani_object object);
    static void SetLoop(ani_env *env, ani_object object, ani_boolean isLoop);
    static ani_boolean GetLoop(ani_env *env, ani_object object);
    static ani_double GetCurrentTime(ani_env *env, ani_object object);
    static ani_double GetDuration(ani_env *env, ani_object object);
    static ani_double GetVideoScaleType(ani_env *env, ani_object object);
    static void SetVideoScaleType(ani_env *env, ani_object object, ani_enum_item videoScaleType);
    static void SetSpeed(ani_env *env, ani_object object, ani_enum_item speed);
    static ani_object GetAudioRendererInfo(ani_env *env, ani_object object);
    static void SetAudioRendererInfo(ani_env *env, ani_object object, ani_object infoObj);
    static void SetVolume(ani_env *env, ani_object object, ani_double volume);
    static ani_object GetTrackDescriptionSync(ani_env *env, ani_object object);
    static void ResetSync(ani_env *env, ani_object object);
    static void Seekmode(ani_env *env, ani_object object, ani_double timeMs, ani_enum_item mode);
    static void SeekWithoutmode(ani_env *env, ani_object object, ani_double timeMs);
    static void PrepareSync(ani_env *env, ani_object object);
    static void PauseSync(ani_env *env, ani_object object);
    static void PlaySync(ani_env *env, ani_object object);
    static void StopSync(ani_env *env, ani_object object);
    static void OnSync(ani_env *env, ani_object object, ani_string type, ani_object callbackOn);
    static void OffSync(ani_env *env, ani_object object, ani_string type);
    static ani_string GetState(ani_env *env, ani_object object);
    static void SetSurfaceId(ani_env *env, ani_object object, ani_string surfaceId);
    static ani_string GetSurfaceId(ani_env *env, ani_object object);
    static void SetUrl(ani_env *env, ani_object object, ani_string url);
    static ani_string GetUrl(ani_env *env, ani_object object);
    void SetSurface(const std::string &surfaceStr);
    void MaxAmplitudeCallbackOn(AVPlayerAni *AVPlayer, std::string callbackName);
    void MaxAmplitudeCallbackOff(AVPlayerAni *AVPlayer, std::string callbackName);
    static PlayerSeekMode TransferSeekMode(int32_t mode);
    bool IsLiveSource();
    bool IsControllable();
    void NotifyDuration(int32_t duration) override;
    void NotifyPosition(int32_t position) override;
    void NotifyState(PlayerStates state) override;
    void NotifyVideoSize(int32_t width, int32_t height) override;
    void NotifyIsLiveStream() override;
    void NotifyDrmInfoUpdated(const std::multimap<std::string, std::vector<uint8_t>> &infos) override;
    int32_t GetJsApiVersion() override;
    void EnqueueNetworkTask(const std::string url);
    void EnqueueFdTask(const int32_t fd);
    void SetSource(std::string url);
    void QueueOnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg);
private:
    void StartListenCurrentResource();
    void PauseListenCurrentResource();
    void ResetUserParameters();

    std::shared_ptr<TaskHandler<TaskRet>> GetTrackDescriptionTask(const std::unique_ptr<AVPlayerContext> &Ctx);
    std::shared_ptr<TaskHandler<TaskRet>> PrepareTask();
    std::shared_ptr<TaskHandler<TaskRet>> PlayTask();
    std::shared_ptr<TaskHandler<TaskRet>> PauseTask();
    std::shared_ptr<TaskHandler<TaskRet>> StopTask();
    std::shared_ptr<TaskHandler<TaskRet>> ResetTask();
    static void SeekEnqueueTask(AVPlayerAni *aniPlayer, int32_t time, int32_t mode);
    std::string GetCurrentState();
    void OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg);
    std::shared_ptr<Player> player_ = nullptr;
    std::atomic<bool> isReleased_ = false;
    PlayerStates state_ = PLAYER_IDLE;
    std::mutex mutex_;
    std::mutex taskMutex_;
    std::atomic<bool> isInterrupted_ = false;
    std::string url_ = "";
    struct AVFileDescriptor fileDescriptor_;
    std::atomic<bool> stopWait_;
    bool avplayerExit_ = false;
    std::condition_variable stateChangeCond_;
    bool isLiveStream_ = false;
    bool calMaxAmplitude_ = false;
    std::shared_ptr<AniAVPlayerCallback> playerCb_ = nullptr;
    std::map<std::string, std::shared_ptr<AutoRef>> refMap_;
    std::shared_mutex drmMutex_{};
    int32_t width_ = 0;
    int32_t height_ = 0;
    int32_t duration_ = -1;
    int32_t position_ = -1;
    std::multimap<std::string, std::vector<uint8_t>> localDrmInfos_;
    std::shared_ptr<MediaDataSourceCallbackAni> dataSrcCb_ = nullptr;
    struct AVDataSrcDescriptor dataSrcDescriptor_;
    std::unique_ptr<TaskQueue> taskQue_;
    bool loop_ = false;
    std::string surface_ = "";
    ani_env *env_ = nullptr;
    int32_t videoScaleType_ = 0;
    OHOS::AudioStandard::AudioRendererInfo audioRendererInfo_ = OHOS::AudioStandard::AudioRendererInfo {
        OHOS::AudioStandard::ContentType::CONTENT_TYPE_MUSIC,
        OHOS::AudioStandard::StreamUsage::STREAM_USAGE_MEDIA,
        0
    };
    OHOS::AudioStandard::InterruptMode interruptMode_ = AudioStandard::InterruptMode::SHARE_MODE;
};

} // namespace Media
} // namespace OHOS

#endif //FRAMEWORKS_ANI_INCLUDE_MEDIA_AVPLAYER_ANI_H
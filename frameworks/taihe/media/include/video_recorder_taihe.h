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
#ifndef VIDEO_RECORDER_TAIHE_H_
#define VIDEO_RECORDER_TAIHE_H_

#include "recorder.h"
#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "recoder_callback_taihe.h"

namespace ANI {
namespace Media {
using namespace taihe;
using namespace ohos::multimedia::media;
using namespace OHOS::Media;

namespace VideoRecorderState {
    const std::string STATE_IDLE = "idle";
    const std::string STATE_PREPARED = "prepared";
    const std::string STATE_PLAYING = "playing";
    const std::string STATE_PAUSED = "paused";
    const std::string STATE_STOPPED = "stopped";
    const std::string STATE_ERROR = "error";
};

struct VideoRecorderAsyncContext;

constexpr int32_t DEFAULT_AUDIO_BIT_RATE = 48000;
constexpr int32_t DEFAULT_AUDIO_CHANNELS = 2;
constexpr int32_t DEFAULT_AUDIO_SAMPLE_RATE = 48000;
constexpr int32_t DEFAULT_DURATION = 5;
constexpr int32_t DEFAULT_VIDEO_BIT_RATE = 48000;
constexpr int32_t DEFAULT_FRAME_HEIGHT = -1;
constexpr int32_t DEFAULT_FRAME_WIDTH = -1;
constexpr int32_t DEFAULT_FRAME_RATE = 30;

class VideoRecorderImpl {
public:
    VideoRecorderImpl();
    bool IsSurfaceIdValid(uint64_t surfaceID);
    void CancelCallback();
    void PrepareSync(VideoRecorderConfig const& config);
    optional<string> GetInputSurfaceSync();
    void StartSync();
    void PauseSync();
    void StopSync();
    void ResumeSync();
    void ReleaseSync();
    void ResetSync();
    string GetState();

    void SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void OnError(callback_view<void(uintptr_t)> callback);
    struct VideoRecorderProfile {
        int32_t audioBitrate = DEFAULT_AUDIO_BIT_RATE;
        int32_t audioChannels = DEFAULT_AUDIO_CHANNELS;
        OHOS::Media::AudioCodecFormat audioCodecFormat = OHOS::Media::AudioCodecFormat::AUDIO_DEFAULT;
        int32_t audioSampleRate = DEFAULT_AUDIO_SAMPLE_RATE;
        int32_t duration = DEFAULT_DURATION;
        OHOS::Media::OutputFormatType outputFormat = OHOS::Media::OutputFormatType::FORMAT_DEFAULT;
        int32_t videoBitrate = DEFAULT_VIDEO_BIT_RATE;
        OHOS::Media::VideoCodecFormat videoCodecFormat = OHOS::Media::VideoCodecFormat::VIDEO_DEFAULT;
        int32_t videoFrameWidth = DEFAULT_FRAME_HEIGHT;
        int32_t videoFrameHeight = DEFAULT_FRAME_WIDTH;
        int32_t videoFrameRate = DEFAULT_FRAME_RATE;
    };
    struct VideoRecorderProperties {
        OHOS::Media::AudioSourceType audioSourceType; // source type;
        OHOS::Media::VideoSourceType videoSourceType;
        VideoRecorderProfile profile;
        int32_t orientationHint = 0; // Optional
        OHOS::Media::Location location; // Optional
        std::string url;
    };

    void GetConfig(const VideoRecorderConfig &config, std::unique_ptr<VideoRecorderAsyncContext> &ctx,
        VideoRecorderProperties &properties);
    int32_t SetUrl(const std::string &urlPath);
    int32_t GetVideoRecorderProperties(VideoRecorderConfig const& config, VideoRecorderProperties &properties);
    int32_t SetVideoRecorderProperties(std::unique_ptr<VideoRecorderAsyncContext> &ctx,
        const VideoRecorderProperties &properties);
private:
    bool isPureVideo = false;
    std::string currentStates_ = VideoRecorderState::STATE_IDLE;
    std::shared_ptr<Recorder> recorder_ = nullptr;
    OHOS::sptr<OHOS::Surface> surface_;
    std::shared_ptr<RecorderCallback> callback_ = nullptr;
    std::map<std::string, std::shared_ptr<AutoRef>> refMap_;
    int32_t videoSourceID;
    int32_t audioSourceID;
};

struct VideoRecorderAsyncContext {
    VideoRecorderAsyncContext() = default;
    ~VideoRecorderAsyncContext() = default;
    void SignError(int32_t code, const std::string &message, bool del = true);

    bool errFlag = false;
    int32_t errCode = 0;
    std::string errMessage = "";
    bool delFlag = true;
    VideoRecorderImpl *taihe = nullptr;
};

class VideoRecorderConfigImpl {
public:
    VideoRecorderConfigImpl();
    std::string GetUrl();
    void SetUrl(string_view url);

private:
};

} // namespace Media
} // namespace ANI
#endif // VIDEO_RECORDER_TAIHE_H_
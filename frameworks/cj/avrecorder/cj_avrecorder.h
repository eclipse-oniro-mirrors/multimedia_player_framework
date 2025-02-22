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

#ifndef CJ_AV_RECORDER_H
#define CJ_AV_RECORDER_H

#include "avrecorder_common.h"
#include "recorder.h"
#include "av_common.h"
#include "media_errors.h"
#include "task_queue.h"
#include "recorder_profiles.h"
#include "buffer/avbuffer.h"
#include "ffi_remote_data.h"

namespace OHOS {
namespace Media {

namespace CjAVRecorderState {
const std::string STATE_IDLE = "idle";
const std::string STATE_PREPARED = "prepared";
const std::string STATE_STARTED = "started";
const std::string STATE_PAUSED = "paused";
const std::string STATE_STOPPED = "stopped";
const std::string STATE_RELEASED = "released";
const std::string STATE_ERROR = "error";
}

namespace CjAVRecordergOpt {
const std::string PREPARE = "Prepare";
const std::string SET_ORIENTATION_HINT = "SetOrientationHint";
const std::string GETINPUTSURFACE = "GetInputSurface";
const std::string START = "Start";
const std::string PAUSE = "Pause";
const std::string RESUME = "Resume";
const std::string STOP = "Stop";
const std::string RESET = "Reset";
const std::string RELEASE = "Release";
const std::string GET_AV_RECORDER_PROFILE = "GetAVRecorderProfile";
const std::string GET_AV_RECORDER_CONFIG = "GetAVRecorderConfig";
const std::string GET_CURRENT_AUDIO_CAPTURER_INFO = "GetCurrentAudioCapturerInfo";
const std::string GET_MAX_AMPLITUDE = "GetMaxAmplitude";
const std::string GET_ENCODER_INFO = "GetEncoderInfo";
}

constexpr int32_t AVRECORDER_DEFAULT_AUDIO_BIT_RATE = 48000;
constexpr int32_t AVRECORDER_DEFAULT_AUDIO_CHANNELS = 2;
constexpr int32_t AVRECORDER_DEFAULT_AUDIO_SAMPLE_RATE = 48000;
constexpr int32_t AVRECORDER_DEFAULT_VIDEO_BIT_RATE = 48000;
constexpr int32_t AVRECORDER_DEFAULT_FRAME_HEIGHT = -1;
constexpr int32_t AVRECORDER_DEFAULT_FRAME_WIDTH = -1;
constexpr int32_t AVRECORDER_DEFAULT_FRAME_RATE = 30;
constexpr int32_t INVALID_AV_VALUE = -1;
constexpr int32_t ERROR_CODE_INVALID_PARAM = 401;

const std::map<std::string, std::vector<std::string>> STATE_CTRL_LIST = {
    {CjAVRecorderState::STATE_IDLE, {
        CjAVRecordergOpt::PREPARE,
        CjAVRecordergOpt::RESET,
        CjAVRecordergOpt::RELEASE,
        CjAVRecordergOpt::GET_AV_RECORDER_PROFILE,
        CjAVRecordergOpt::GET_ENCODER_INFO
    }},
    {CjAVRecorderState::STATE_PREPARED, {
        CjAVRecordergOpt::SET_ORIENTATION_HINT,
        CjAVRecordergOpt::GETINPUTSURFACE,
        CjAVRecordergOpt::START,
        CjAVRecordergOpt::RESET,
        CjAVRecordergOpt::RELEASE,
        CjAVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO,
        CjAVRecordergOpt::GET_MAX_AMPLITUDE,
        CjAVRecordergOpt::GET_ENCODER_INFO,
        CjAVRecordergOpt::GET_AV_RECORDER_CONFIG,
    }},
    {CjAVRecorderState::STATE_STARTED, {
        CjAVRecordergOpt::START,
        CjAVRecordergOpt::RESUME,
        CjAVRecordergOpt::PAUSE,
        CjAVRecordergOpt::STOP,
        CjAVRecordergOpt::RESET,
        CjAVRecordergOpt::RELEASE,
        CjAVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO,
        CjAVRecordergOpt::GET_MAX_AMPLITUDE,
        CjAVRecordergOpt::GET_ENCODER_INFO,
        CjAVRecordergOpt::GET_AV_RECORDER_CONFIG,
    }},
    {CjAVRecorderState::STATE_PAUSED, {
        CjAVRecordergOpt::PAUSE,
        CjAVRecordergOpt::RESUME,
        CjAVRecordergOpt::STOP,
        CjAVRecordergOpt::RESET,
        CjAVRecordergOpt::RELEASE,
        CjAVRecordergOpt::GET_CURRENT_AUDIO_CAPTURER_INFO,
        CjAVRecordergOpt::GET_MAX_AMPLITUDE,
        CjAVRecordergOpt::GET_ENCODER_INFO,
        CjAVRecordergOpt::GET_AV_RECORDER_CONFIG,
    }},
    {CjAVRecorderState::STATE_STOPPED, {
        CjAVRecordergOpt::STOP,
        CjAVRecordergOpt::PREPARE,
        CjAVRecordergOpt::RESET,
        CjAVRecordergOpt::RELEASE,
        CjAVRecordergOpt::GET_ENCODER_INFO,
        CjAVRecordergOpt::GET_AV_RECORDER_CONFIG
    }},
    {CjAVRecorderState::STATE_RELEASED, {
        CjAVRecordergOpt::RELEASE
    }},
    {CjAVRecorderState::STATE_ERROR, {
        CjAVRecordergOpt::RESET,
        CjAVRecordergOpt::RELEASE
    }},
};

struct CjAVRecorderProfile {
    int32_t audioBitrate = AVRECORDER_DEFAULT_AUDIO_BIT_RATE;
    int32_t audioChannels = AVRECORDER_DEFAULT_AUDIO_CHANNELS;
    int32_t audioSampleRate = AVRECORDER_DEFAULT_AUDIO_SAMPLE_RATE;
    AudioCodecFormat audioCodecFormat = AudioCodecFormat::AUDIO_DEFAULT;
    int32_t videoBitrate = AVRECORDER_DEFAULT_VIDEO_BIT_RATE;
    int32_t videoFrameWidth = AVRECORDER_DEFAULT_FRAME_HEIGHT;
    int32_t videoFrameHeight = AVRECORDER_DEFAULT_FRAME_WIDTH;
    int32_t videoFrameRate = AVRECORDER_DEFAULT_FRAME_RATE;
    bool isHdr = false;
    bool enableTemporalScale = false;
    VideoCodecFormat videoCodecFormat = VideoCodecFormat::VIDEO_DEFAULT;
    OutputFormatType fileFormat = OutputFormatType::FORMAT_DEFAULT;
};

struct CjAVRecorderConfig {
    AudioSourceType audioSourceType;
    VideoSourceType videoSourceType;
    CjAVRecorderProfile profile;
    std::string url;
    int32_t rotation = 0;
    int32_t maxDuration = INT32_MAX;
    Location location;
    AVMetadata metadata;
    FileGenerationMode fileGenerationMode = FileGenerationMode::APP_CREATE;
    bool withVideo = false;
    bool withAudio = false;
    bool withLocation = false;
};

using RetInfo = std::pair<int32_t, std::string>;
char *MallocCString(const std::string &origin);

class CjAVRecorder : public OHOS::FFI::FFIData {
    DECL_TYPE(CjAVRecorder, OHOS::FFI::FFIData)
public:
    CjAVRecorder() = default;
    ~CjAVRecorder() = default;
    static int64_t CreateAVRecorder(int32_t *errCode);
    int32_t Prepare(CAVRecorderConfig config);
    char *GetInputSurface(int32_t *errCode);
    int32_t GetState(std::string& state);
    int32_t Start();
    int32_t Pause();
    int32_t Resume();
    int32_t Stop();
    int32_t Reset();
    int32_t Release();
    CAVRecorderConfig GetAVRecorderConfig(int32_t *errCode);
    int32_t GetAudioCapturerMaxAmplitude(int32_t *errCode);
    int32_t GetCurrentAudioCapturerInfo(AudioRecorderChangeInfo &changeInfo);
    int32_t GetAvailableEncoder(std::vector<EncoderCapabilityData> &encoderInfo);
    void UpdateRotation(int32_t rotation, int32_t *errCode);
    std::shared_ptr<RecorderCallback> recorderCb_ = nullptr;
private:
    std::shared_ptr<Recorder> recorder_ = nullptr; //
    std::map<MetaSourceType, int32_t> metaSourceIDMap_;
    sptr<Surface> surface_ = nullptr;
    uint64_t surfaceId_ = 0;
    std::mutex mutex_;
    std::string currentState_ = CjAVRecorderState::STATE_IDLE; // set callback
    std::shared_ptr<CjAVRecorderConfig> config_ = nullptr;
    bool hasConfiged_ = false;
    int32_t videoSourceID_ = -1;
    int32_t audioSourceID_ = -1;
    bool getVideoInputSurface_ = false;
    bool withVideo_ = false;

    void StateCallback(const std::string &state);
    void MediaProfileLog(bool isVideo, CjAVRecorderProfile &profile);
    void RemoveSurface();
    RetInfo SetAVConfigParams();
    RetInfo SetConfigUrl(std::shared_ptr<CjAVRecorderConfig> config);
    RetInfo SetProfile(std::shared_ptr<CjAVRecorderConfig> config);
    int32_t GetProfile(CAVRecorderProfile profile);
    int32_t GetOutputFormat(const std::string &extension, OutputFormatType &type);
    int32_t GetVideoCodecFormat(const std::string &mime, VideoCodecFormat &codecFormat);
    int32_t GetAudioCodecFormat(const std::string &mime, AudioCodecFormat &codecFormat);
    int32_t GetModeAndUrl(CAVRecorderConfig config);
    int32_t GetAVMetaData(CAVMetadata metaData);
    int32_t GetSourceType(CAVRecorderConfig config);
    int32_t GetConfig(CAVRecorderConfig config);
    int32_t CheckStateMachine(const std::string &opt);
    int32_t CheckRepeatOperation(const std::string &opt);
    int32_t ToCAVRecorderConfig(CAVRecorderConfig &retConfig);
    int32_t SetFileFormat(OutputFormatType &type, std::string &extension);
    int32_t SetVideoCodecFormat(VideoCodecFormat &codecFormat, std::string &mime);
    int32_t SetAudioCodecFormat(AudioCodecFormat &codecFormat, std::string &mime);
    RetInfo GetRetInfo(int32_t errCode, const std::string &opt, const std::string &param, const std::string &add = "");
    int32_t DoGetAVRecorderConfig(std::shared_ptr<CjAVRecorderConfig> &config);
    RetInfo DoGetInputSurface();
    RetInfo DoStart();
    RetInfo DoPause();
    RetInfo DoResume();
    RetInfo DoStop();
    RetInfo DoReset();
    RetInfo DoRelease();
    RetInfo DealTask(std::string opt);
    RetInfo ExecuteOptTask(const std::string &opt);
};
} // namespace Media
} // namespace OHOS
#endif // CJ_AV_RECORDER_H
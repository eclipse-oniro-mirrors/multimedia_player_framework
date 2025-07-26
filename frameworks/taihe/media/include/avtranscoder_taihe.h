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
#ifndef AVTRANSCODER_TAIHE_H
#define AVTRANSCODER_TAIHE_H

#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "transcoder.h"
#include "task_queue.h"
#include "media_ani_common.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;
using namespace OHOS::Media;

using RetInfo = std::pair<int32_t, std::string>;

namespace AVTransCoderState {
    const std::string STATE_IDLE = "idle";
    const std::string STATE_PREPARED = "prepared";
    const std::string STATE_STARTED = "started";
    const std::string STATE_PAUSED = "paused";
    const std::string STATE_CANCELLED = "cancelled";
    const std::string STATE_COMPLETED = "completed";
    const std::string STATE_RELEASED = "released";
    const std::string STATE_ERROR = "error";
}

namespace AVTransCoderOpt {
    const std::string PREPARE = "Prepare";
    const std::string START = "Start";
    const std::string PAUSE = "Pause";
    const std::string RESUME = "Resume";
    const std::string CANCEL = "Cancel";
    const std::string RELEASE = "Release";
    const std::string SET_AV_TRANSCODER_CONFIG = "SetAVTransCoderConfig";
}

constexpr int32_t AVTRANSCODER_DEFAULT_AUDIO_BIT_RATE = 48000;
constexpr int32_t AVTRANSCODER_DEFAULT_VIDEO_BIT_RATE = -1;
constexpr int32_t AVTRANSCODER_DEFAULT_FRAME_HEIGHT = -1;
constexpr int32_t AVTRANSCODER_DEFAULT_FRAME_WIDTH = -1;

const std::map<std::string, std::vector<std::string>> STATE_LIST = {
    {AVTransCoderState::STATE_IDLE, {
        AVTransCoderOpt::PREPARE,
        AVTransCoderOpt::RELEASE
    }},
    {AVTransCoderState::STATE_PREPARED, {
        AVTransCoderOpt::START,
        AVTransCoderOpt::RELEASE
    }},
    {AVTransCoderState::STATE_STARTED, {
        AVTransCoderOpt::START,
        AVTransCoderOpt::PAUSE,
        AVTransCoderOpt::RESUME,
        AVTransCoderOpt::CANCEL,
        AVTransCoderOpt::RELEASE
    }},
    {AVTransCoderState::STATE_PAUSED, {
        AVTransCoderOpt::START,
        AVTransCoderOpt::PAUSE,
        AVTransCoderOpt::RESUME,
        AVTransCoderOpt::CANCEL,
        AVTransCoderOpt::RELEASE
    }},
    {AVTransCoderState::STATE_CANCELLED, {
        AVTransCoderOpt::RELEASE
    }},
    {AVTransCoderState::STATE_COMPLETED, {
        AVTransCoderOpt::RELEASE
    }},
    {AVTransCoderState::STATE_RELEASED, {
        AVTransCoderOpt::RELEASE
    }},
    {AVTransCoderState::STATE_ERROR, {
        AVTransCoderOpt::RELEASE
    }},
};

namespace AVTransCoderEvent {
    const std::string EVENT_COMPLETE = "complete";
    const std::string EVENT_ERROR = "error";
    const std::string EVENT_PROGRESS_UPDATE = "progressUpdate";
}

struct AVTransCoderAsyncContext;

struct AVTransCoderConfigInner {
    AudioCodecFormat audioCodecFormat = AudioCodecFormat::AUDIO_DEFAULT;
    int32_t audioBitrate = AVTRANSCODER_DEFAULT_AUDIO_BIT_RATE;
    OutputFormatType fileFormat = OutputFormatType::FORMAT_DEFAULT;
    VideoCodecFormat videoCodecFormat = VideoCodecFormat::VIDEO_DEFAULT;
    int32_t videoBitrate = AVTRANSCODER_DEFAULT_VIDEO_BIT_RATE;
    int32_t videoFrameWidth = AVTRANSCODER_DEFAULT_FRAME_WIDTH;
    int32_t videoFrameHeight = AVTRANSCODER_DEFAULT_FRAME_HEIGHT;
};

class AVTranscoderImpl {
public:
    AVTranscoderImpl();
    AVTranscoderImpl(AVTranscoderImpl *obj);

    ohos::multimedia::media::AVFileDescriptor GetFdSrc();
    void SetFdSrc(ohos::multimedia::media::AVFileDescriptor const& fdSrc);
    int32_t GetFdDst();
    void SetFdDst(int32_t fdDst);
    void PrepareSync(AVTranscoderConfig const& config);
    RetInfo Start();
    RetInfo Pause();
    RetInfo Resume();
    RetInfo Cancel();
    RetInfo Release();
    RetInfo SetOutputFile(int32_t fd);

    void PauseSync();
    void ReleaseSync();
    void StartSync();
    void ResumeSync();
    void CancelSync();
    void ExecuteByPromise(AVTranscoderImpl *taihe, const std::string &opt);
    int32_t CheckRepeatOperation(const std::string &opt);
    RetInfo SetInputFile(int32_t fd, int64_t offset, int64_t size);
    int32_t CheckStateMachine(const std::string &opt);
    void StateCallback(const std::string &state);
    void CancelCallback();
    static std::shared_ptr<TaskHandler<RetInfo>> GetPromiseTask(AVTranscoderImpl *taihe, const std::string &opt);
    static std::shared_ptr<TaskHandler<RetInfo>> GetPrepareTask(std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx);
    RetInfo Configure(std::shared_ptr<AVTransCoderConfigInner> config);
    int32_t GetConfig(std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx, AVTranscoderConfig const& config);
    int32_t GetAudioConfig(AVTranscoderConfig const& config, std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx);
    int32_t GetVideoConfig(AVTranscoderConfig const& config, std::unique_ptr<AVTransCoderAsyncContext> &asyncCtx);
    int32_t GetAudioCodecFormat(const std::string &mime, AudioCodecFormat &codecFormat);
    int32_t GetVideoCodecFormat(const std::string &mime, VideoCodecFormat &codecFormat);
    int32_t GetOutputFormat(const std::string &extension, OutputFormatType &type);
    void SetCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &callbackName);

    void OnComplete(callback_view<void(uintptr_t)> callback);
    void OffComplete(optional_view<callback<void(uintptr_t)>> callback);

    void OnError(callback_view<void(uintptr_t)> callback);
    void OffError(optional_view<callback<void(uintptr_t)>> callback);

    void OnProgressUpdate(callback_view<void(int32_t)> callback);
    void OffProgressUpdate(optional_view<callback<void(int32_t)>> callback);

    using AvTransCoderTaskqFunc = RetInfo (AVTranscoderImpl::*)();
private:
    std::shared_ptr<TransCoder> transCoder_ = nullptr;
    std::unique_ptr<TaskQueue> taskQue_;
    std::shared_ptr<TransCoderCallback> transCoderCb_ = nullptr;
    struct OHOS::Media::AVFileDescriptor srcFd_;
    std::string srcUrl_ = "";
    static std::map<std::string, AvTransCoderTaskqFunc> taskQFuncs_;
    bool hasConfiged_ = false;
    std::shared_ptr<AVTransCoderConfigInner> config_ = nullptr;
    std::map<std::string, std::shared_ptr<AutoRef>> eventCbMap_;
    int32_t dstFd_ = -1;
};

struct AVTransCoderAsyncContext {
    explicit AVTransCoderAsyncContext() {}
    ~AVTransCoderAsyncContext() = default;

    void AVTransCoderSignError(int32_t errCode, const std::string &operate,
        const std::string &param, const std::string &add = "");
    void SignError(int32_t code, const std::string &message, bool del = true);
    AVTranscoderImpl *avTransCoder = nullptr;
    std::shared_ptr<AVTransCoderConfigInner> config_ = nullptr;
    std::string opt_ = "";
    std::shared_ptr<TaskHandler<RetInfo>> task_ = nullptr;
    bool errFlag = false;
    int32_t errCode = 0;
    std::string errMessage = "";
    bool delFlag = true;
    AVTranscoderImpl *taihe = nullptr;
};
}
#endif // AVTRANSCODER_TAIHE_H
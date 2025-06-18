/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CJ_AVTRANSCODER_H
#define CJ_AVTRANSCODER_H

#include "ffi_remote_data.h"
#include "transcoder.h"
#include "recorder.h"
#include "avcodec_info.h"
#include "media_log.h"
#include "avtranscoder_ffi.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "CJAVTranscoder"};
}

namespace OHOS {
namespace Media {

struct EnumClassHash {
    template <typename T>
    std::size_t operator()(T t) const
    {
        return static_cast<std::size_t>(t);
    }
};

enum class CJAVTranscoderEvent {
    EVENT_PROGRESS_UPDATE,
    EVENT_COMPLETE,
    EVENT_ERROR
};

enum class CjAVTransCoderState {
    STATE_IDLE,
    STATE_PREPARED,
    STATE_STARTED,
    STATE_PAUSED,
    STATE_CANCELLED,
    STATE_COMPLETED,
    STATE_RELEASED,
    STATE_ERROR
};

enum class CjAVTransCoderOpt {
    PREPARE,
    START,
    PAUSE,
    RESUME,
    CANCEL,
    RELEASE,
    SET_FD
};

constexpr int32_t CJAVTRANSCODER_DEFAULT_AUDIO_BIT_RATE = 48000;
constexpr int32_t CJAVTRANSCODER_DEFAULT_VIDEO_BIT_RATE = -1;
constexpr int32_t CJAVTRANSCODER_DEFAULT_FRAME_HEIGHT = -1;
constexpr int32_t CJAVTRANSCODER_DEFAULT_FRAME_WIDTH = -1;

struct CjAVTransCoderConfig {
    int32_t audioBitrate = CJAVTRANSCODER_DEFAULT_AUDIO_BIT_RATE;
    AudioCodecFormat audioCodecFormat = AudioCodecFormat::AUDIO_DEFAULT;
    OutputFormatType fileFormat = OutputFormatType::FORMAT_DEFAULT;
    int32_t videoBitrate = CJAVTRANSCODER_DEFAULT_VIDEO_BIT_RATE;
    VideoCodecFormat videoCodecFormat = VideoCodecFormat::VIDEO_DEFAULT;
    int32_t videoFrameWidth = CJAVTRANSCODER_DEFAULT_FRAME_HEIGHT;
    int32_t videoFrameHeight = CJAVTRANSCODER_DEFAULT_FRAME_WIDTH;
};

class FFI_EXPORT CJAVTranscoder : public OHOS::FFI::FFIData {
    DECL_TYPE(CJAVTranscoder, OHOS::FFI::FFIData)
public:
    static int64_t CreateAVTranscoder(int32_t* errorcode);
                    
    int32_t Prepare(std::shared_ptr<TransCoder> transCoder, const CAVTransCoderConfig &cconfig);
    int32_t Start(std::shared_ptr<TransCoder> transCoder);
    int32_t Pause(std::shared_ptr<TransCoder> transCoder);
    int32_t Resume(std::shared_ptr<TransCoder> transCoder);
    int32_t Cancel(std::shared_ptr<TransCoder> transCoder);
    int32_t Release(std::shared_ptr<TransCoder> transCoder);

    CAVFileDescriptor GetInputFile();
    int32_t SetInputFile(std::shared_ptr<TransCoder> transCoder, CAVFileDescriptor fdSrc);

    int32_t GetOutputFile();
    int32_t SetOutputFile(std::shared_ptr<TransCoder> transCoder, int32_t fdDst);

    int32_t OnProgressUpdate(int64_t callbackId);
    int32_t OffProgressUpdate();
    int32_t OnComplete(int64_t callbackId);
    int32_t OffComplete();
    int32_t OnError(int64_t callbackId);
    int32_t OffError();

    std::shared_ptr<TransCoder> transCoder_ = nullptr;
    std::shared_ptr<TransCoderCallback> transCoderCb_ = nullptr;

private:
    bool hasConfiged_ = false;
    
    struct AVFileDescriptor fdSrc_;
    int32_t fdDst_;

    int32_t GetReturnRet(int32_t errCode);
    int32_t GetAudioCodecFormat(const std::string &mime, AudioCodecFormat &codecFormat);
    int32_t GetVideoCodecFormat(const std::string &mime, VideoCodecFormat &codecFormat);
    int32_t GetOutputFormat(const std::string &extension, OutputFormatType &type);
    int32_t GetConfig(const CAVTransCoderConfig &cconfig, CjAVTransCoderConfig &config);

    void StateCallback(CjAVTransCoderState state);
    void CancelCallback();
    int32_t CheckStateMachine(CjAVTransCoderOpt opt);
    int32_t CheckRepeatOperation(CjAVTransCoderOpt opt);
};
}
}

#endif // CJ_AVTRANSCODER_H
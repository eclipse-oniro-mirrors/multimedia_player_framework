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
#ifndef LPP_ADEC_ADAPTER_H
#define LPP_ADEC_ADAPTER_H

#include <string>
#include <mutex>

#include "refbase.h"
#include "pipeline/pipeline.h"
#include "buffer/avbuffer.h"
#include "buffer/avbuffer_queue.h"
#include "buffer/avbuffer_queue_producer.h"
#include "avcodec_audio_codec.h"
#include "avcodec_common.h"
#include "media_codec/media_codec.h"

namespace OHOS {
namespace Media {
using namespace Pipeline;

class LppAudioDecoderAdapter : public std::enable_shared_from_this<LppAudioDecoderAdapter> {
public:
    explicit LppAudioDecoderAdapter(const std::string &streamerId);

    virtual ~LppAudioDecoderAdapter();

    int32_t SetParameter(const Format &params);

    int32_t Init(const std::string &name);

    int32_t Configure(const Format &params);

    int32_t SetOutputBufferQueue(const sptr<Media::AVBufferQueueProducer> &bufferQueueProducer);

    int32_t Prepare();

    int32_t Start();

    int32_t Pause();

    int32_t Flush();

    int32_t Resume();

    int32_t Stop();

    sptr<Media::AVBufferQueueProducer> GetInputBufferQueue();

    void OnBufferAvailable(bool isOutputBuffer);
    void HandleBufferAvailable(bool isOutputBuffer, bool isFlushed);
    void OnError(CodecErrorType errorType, int32_t errorCode);
    void SetEventReceiver(std::shared_ptr<EventReceiver> eventReceiver);

private:
    void FlushTask();
    int64_t GeneratedJobIdx();
    bool IsJobFlushed(int64_t jobIdx);

    std::string streamerId_ {};
    std::shared_ptr<MediaCodec> audiocodec_ {nullptr};
    sptr<Media::AVBufferQueueProducer> outputBufferQueueProducer_ {nullptr};
    std::unique_ptr<OHOS::Media::Task> decodertask_ {nullptr};
    std::mutex jobIdxMutex_ {};
    int64_t jobIdx_ {0};
    int64_t jobIdxBase_ {0};
    std::shared_ptr<EventReceiver> eventReceiver_ {nullptr};
};
}
}
#endif // LPP_ADEC_ADAPTER_H
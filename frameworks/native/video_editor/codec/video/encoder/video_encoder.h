/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_VEF_VIDEO_ENCODER_H
#define OH_VEF_VIDEO_ENCODER_H

#include <mutex>
#include <string>
#include <functional>
#include <native_avcodec_base.h>
#include <native_avmuxer.h>
#include "ffrt.h"
#include "video_editor.h"

namespace OHOS {
namespace Media {
using OnNewOutputDataCallBack = std::function<void(OH_AVMemory* data, OH_AVCodecBufferAttr* attr)>;

class VideoEncoder {
public:
    VideoEncoder(uint64_t id, const OnNewOutputDataCallBack& cb);
    ~VideoEncoder();

    VEFError Init(OH_AVFormat* format);
    VEFError Start();
    VEFError Stop();
    VEFError SendEos();
    VEFError Flush();
    OHNativeWindow* GetOHNativeWindow() const;

    static void CodecOnStreamChanged(OH_AVCodec* codec, OH_AVFormat* format, void* userData);
    static void CodecOnNeedInputData(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data, void* userData);
    static void CodecOnError(OH_AVCodec* codec, int32_t errorCode, void* userData);
    static void CodecOnNewOutputData(OH_AVCodec* codec, uint32_t index, OH_AVMemory* data, OH_AVCodecBufferAttr* attr,
        void* userData);

private:
    VEFError CreateEncoder(OH_AVFormat* format);
    VEFError ConfigureEncoder(OH_AVFormat* format);
    VEFError WriteFrame(OH_AVMemory* data, OH_AVCodecBufferAttr* attr);

private:
    std::string logTag_ = "";
    ffrt::mutex encoderMutex_;
    OH_AVCodec* encoder_ = nullptr;
    std::atomic_bool codecState_ = false;
    OHNativeWindow* nativeWindow_ = nullptr;
    OnNewOutputDataCallBack onNewOutputDataCallBack_ = nullptr;
};
} // namespace Media
} // namespace OHOS

#endif // OH_VEF_VIDEO_ENCODER_H

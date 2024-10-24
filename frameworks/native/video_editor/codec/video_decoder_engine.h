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

#ifndef OH_VEF_VIDEO_DECODER_ENGINE_H
#define OH_VEF_VIDEO_DECODER_ENGINE_H

#include <memory>
#include "video_editor.h"
#include "native_avcodec_base.h"

namespace OHOS {
namespace Media {

enum class VideoDecodeResult : uint32_t {
    SUCCESS,
    FAILED,
    CANCELED
};

class VideoDecodeCallback {
public:
    virtual void OnDecodeFrame(uint64_t pts) = 0;
    virtual void OnDecodeResult(VideoDecodeResult result) = 0;
};

class IVideoDecoderEngine {
public:
    static std::shared_ptr<IVideoDecoderEngine> Create(int fd, std::weak_ptr<VideoDecodeCallback> cb);

    virtual uint64_t GetId() const = 0;
    virtual VEFError StartDecode() = 0;
    virtual VEFError StopDecode() = 0;
    virtual VEFError SetNativeWindow(OHNativeWindow* surfaceWindow) = 0;
    virtual OH_AVFormat* GetVideoFormat() = 0;
    virtual int32_t GetColorRange() = 0;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_VIDEO_DECODER_ENGINE_H
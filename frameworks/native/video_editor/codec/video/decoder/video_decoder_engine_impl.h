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

#ifndef OH_VEF_VIDEO_DECODER_ENGINE_IMPL_H
#define OH_VEF_VIDEO_DECODER_ENGINE_IMPL_H

#include <string>
#include "native_avsource.h"
#include "codec/video_decoder_engine.h"

namespace OHOS {
namespace Media {

class VideoDecoderEngineImpl : public IVideoDecoderEngine, public VideoDecodeCallback {
public:
    VideoDecoderEngineImpl(uint64_t id, int fd, std::weak_ptr<VideoDecodeCallback> cb);
    virtual ~VideoDecoderEngineImpl();

public:
    uint64_t GetId() const override;
    VEFError SetNativeWindow(OHNativeWindow* surfaceWindow) override;
    VEFError StartDecode() override;
    VEFError StopDecode() override;
    OH_AVFormat* GetVideoFormat() override;

    void OnDecodeFrame(uint64_t pts) override;
    void OnDecodeResult(VideoDecodeResult result) override;

    VEFError Init();

private:
    uint64_t id_ = 0;
    int fd_ = -1;
    std::string logTag_;
    std::weak_ptr<VideoDecodeCallback> cb_;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_VIDEO_DECODER_ENGINE_IMPL_H
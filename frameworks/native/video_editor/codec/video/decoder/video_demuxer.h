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

#ifndef OH_VEF_VIDEO_DEMUXER_H
#define OH_VEF_VIDEO_DEMUXER_H

#include <string>
#include <native_avcodec_base.h>
#include <native_avdemuxer.h>
#include "video_editor.h"

namespace OHOS {
namespace Media {
class VideoDeMuxer {
public:
    VideoDeMuxer(uint64_t id, int fd);
    ~VideoDeMuxer();

    VEFError Init();
    OH_AVFormat* GetVideoFormat() const;
    OH_AVFormat* GetAudioFormat() const;
    OH_AVFormat* GetSourceFormat() const;
    VEFError ReadVideoData(OH_AVMemory* data, OH_AVCodecBufferAttr* attr);
    VEFError ReadAudioData(OH_AVMemory* data, OH_AVCodecBufferAttr* attr);

private:
    VEFError ParseTrackInfo();

private:
    int fd_ = -1;
    std::string logTag_ = "";
    int32_t videoTrackId_ = -1;
    int32_t audioTrackId_ = -1;
    OH_AVSource* source_ = { nullptr };
    OH_AVDemuxer* deMuxer_ = { nullptr };
    OH_AVFormat* sourceFormat_ = { nullptr };
    OH_AVFormat* videoFormat_ = { nullptr };
    OH_AVFormat* audioFormat_ = { nullptr };
};
} // namespace Media
} // namespace OHOS

#endif // OH_VEF_VIDEO_DEMUXER_H

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
#ifndef AVIMAGEGENERATOR_TAIHE_H
#define AVIMAGEGENERATOR_TAIHE_H

#include "ohos.multimedia.media.proj.hpp"
#include "ohos.multimedia.media.impl.hpp"
#include "taihe/runtime.hpp"
#include "avmetadatahelper.h"
#include "audio_info.h"
#include "player.h"
#include "media_core.h"

namespace ANI::Media {
using namespace taihe;
using namespace ohos::multimedia::media;

class AVImageGeneratorImpl {
public:
    AVImageGeneratorImpl();
    AVImageGeneratorImpl(std::shared_ptr<OHOS::Media::AVMetadataHelper> avMetadataHelper);
    optional<AVFileDescriptor> GetFdSrc();
    void SetFdSrc(optional_view<AVFileDescriptor> fdSrc);
    optional<::ohos::multimedia::image::image::PixelMap> FetchFrameByTimeSync(int64_t timeUs,
        AVImageQueryOptions options, PixelMapParams const& param);
    optional<::ohos::multimedia::image::image::PixelMap> FetchScaledFrameByTimeSync(int64_t timeUs,
        AVImageQueryOptions options, optional_view<OutputSize> param);
    void ReleaseSync();
private:
    std::shared_ptr<OHOS::Media::AVMetadataHelper> helper_;
    struct OHOS::Media::AVFileDescriptor fileDescriptor_;
    OHOS::Media::HelperState state_ { OHOS::Media::HelperState::HELPER_STATE_IDLE };
};
} // namespace ANI::Media
#endif // AVIMAGEGENERATOR_TAIHE_H
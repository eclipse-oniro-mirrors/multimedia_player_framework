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

#ifndef FRAMEWORKS_ANI_INCLUDE_MEDIA_AV_IMAGE_GENERATOR_ANI_H
#define FRAMEWORKS_ANI_INCLUDE_MEDIA_AV_IMAGE_GENERATOR_ANI_H

#include <ani.h>
#include "avmetadatahelper.h"
#include "pixel_map_ani.h"
#include "media_core.h"

namespace OHOS {
namespace Media {

class AVImageGeneratorAni {
public:
    AVImageGeneratorAni(std::shared_ptr<AVMetadataHelper> avImageGenerator);
    AVImageGeneratorAni();
    ~AVImageGeneratorAni();
    static ani_status AVImageGeneratorInit(ani_env *env);
    static ani_object Constructor([[maybe_unused]] ani_env *env);
    static AVImageGeneratorAni* Unwrapp(ani_env *env, ani_object object);
    static ani_object FetchFrameByTime(ani_env *env, ani_object object, ani_double timeUs,
        ani_enum_item avImageQueryOptions, ani_object param);
    static void ParseParamsInner(ani_env *env, ani_object param, int32_t &width, int32_t &height,
        int32_t &colorFormat);
    static void Release(ani_env *env, ani_object object);
    static void SetFdSrc(ani_env *env, ani_object object, ani_int fd, ani_int offset, ani_int size);
    static ani_object GetFdSrc(ani_env *env, ani_object object);
private:
    std::shared_ptr<AVMetadataHelper> helper_ = nullptr;
    std::atomic<HelperState> state_ = HelperState::HELPER_STATE_RUNNABLE;
    std::shared_ptr<PixelMap> pixel_ = nullptr;
    std::shared_ptr<AVMetadataHelper> helperPtr = nullptr;
    struct AVFileDescriptor fileDescriptor_ ;
};

struct AVImageGeneratorAsyncContext {
    AVImageGeneratorAni *ani = nullptr;
};

} // namespace Media
} // namespace OHOS

#endif //FRAMEWORKS_ANI_INCLUDE_MEDIA_AV_IMAGE_GENERATOR_ANI_H
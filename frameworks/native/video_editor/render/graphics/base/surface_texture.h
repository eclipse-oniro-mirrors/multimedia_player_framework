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

#ifndef OH_VEF_GRAPHICS_SURFACE_TEXTURE_H
#define OH_VEF_GRAPHICS_SURFACE_TEXTURE_H

#include <mutex>
#include <GLES3/gl3.h>
#include "native_image.h"

namespace OHOS {
namespace Media {
class SurfaceTexture {
public:
    std::shared_ptr<OH_NativeImage> nativeImage_{ nullptr };

    OHNativeWindow* nativeWindow_{ nullptr };
    GLuint nativeTexId_{ GL_NONE };

    static void OnFrameAvailable(void* context);
    void AwaitNativeImage();

private:
    std::mutex frameLock_;
    std::condition_variable frameCv_;
    int32_t frameNum_ = 0;
};
}
}

#endif
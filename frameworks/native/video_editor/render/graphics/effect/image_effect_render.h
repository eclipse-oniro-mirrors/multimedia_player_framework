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

#ifndef OH_VEF_GRAPHICS_IMAGE_EFFECT_RENDER_H
#define OH_VEF_GRAPHICS_IMAGE_EFFECT_RENDER_H

#include "image_effect.h"
#include "render/graphics/base/render_texture.h"
#include "video_editor.h"

namespace OHOS {
namespace Media {
class ImageEffectRender : public RenderObject {
public:
    explicit ImageEffectRender(const std::shared_ptr<OH_ImageEffect>& imageEffect);
    ~ImageEffectRender();
    bool Init() override;
    bool Release() override;
    RenderTexturePtr Render(RenderContext *context, RenderSurface* surface, const RenderTexturePtr& inputRenderTexture,
        const int32_t colorRange);

private:
    VEFError CreateNativeBuffer(int32_t width, int32_t height, GLuint textureId,
        OH_NativeBuffer** nativeBuffer, OHNativeWindowBuffer** nativeWindowBuffer);
    VEFError InitNativeBuffer(int32_t width, int32_t height);
    void ReleaseNativeBuffer();

private:
    std::shared_ptr<OH_ImageEffect> imageEffect_ { nullptr };
    GLuint tempTexForEffect_ {GL_NONE};
    OH_NativeBuffer *nativeBuffer_ = { nullptr };
    OHNativeWindowBuffer *nativeWindowBuffer_ { nullptr };
    int32_t colorRange_ { -1 };
};
}
}

#endif
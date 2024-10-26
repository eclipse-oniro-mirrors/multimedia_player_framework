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

#ifndef OH_VEF_GRAPHICS_SHADER_PASS_SURFACE_H
#define OH_VEF_GRAPHICS_SHADER_PASS_SURFACE_H

#include <GLES3/gl3.h>
#include "render/graphics/base/math/render_matrix.h"
#include "shader_pass.h"

namespace OHOS {
namespace Media {
class SurfaceData : public RenderEffectData {
public:
    Mat4x4 uTexMatrix;
    GLuint nativeTexId;
};
using SurfaceDataPtr = std::shared_ptr<SurfaceData>;

class ShaderPassSurface : public ShaderPass {
public:
    explicit ShaderPassSurface(RenderContext* context);
    ~ShaderPassSurface() override;

    SurfaceDataPtr GetRenderEffectData();

protected:
    void PreDraw() override;
    void PostDraw() override;
};
using ShaderPassSurfacePtr = std::shared_ptr<ShaderPassSurface>;
}
}

#endif
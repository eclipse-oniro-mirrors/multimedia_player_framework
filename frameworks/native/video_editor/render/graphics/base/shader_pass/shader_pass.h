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

#ifndef OH_VEF_GRAPHICS_SHADER_PASS_H
#define OH_VEF_GRAPHICS_SHADER_PASS_H

#include "render/graphics/base/render_texture.h"
#include <vector>

namespace OHOS {
namespace Media {
class ShaderPassProgram;
class RenderMesh;

extern const std::vector<std::vector<float>> DEFAULT_VERTEX_DATA;
extern const std::vector<std::vector<float>> DEFAULT_FLIP_VERTEX_DATA;

class RenderEffectData {
public:
    virtual ~RenderEffectData() {}

    RenderTexturePtr inputTexture_ = nullptr;
    GLsizei outputWidth_;
    GLsizei outputHeight_;
};

using RenderEffectDataPtr = std::shared_ptr<RenderEffectData>;

class ShaderPass {
public:
    ShaderPass(RenderContext* context, std::string vertexShaderCode, std::string fragmentShaderCode,
        const std::vector<std::vector<float>>& meshData);
    virtual ~ShaderPass();

    virtual RenderTexturePtr Render();

protected:
    RenderEffectDataPtr renderEffectData_;
    RenderContext* context_{ nullptr };
    std::string vertexShaderCode_;
    std::string fragmentShaderCode_;
    GLuint fbo_{ 0 };
    std::shared_ptr<ShaderPassProgram> shader_{ nullptr };
    std::shared_ptr<RenderMesh> renderMesh_{ nullptr };

    virtual void PreDraw() = 0;
    virtual void PostDraw() = 0;
};

using ShaderPassPtr = std::shared_ptr<ShaderPass>;
}
}

#endif
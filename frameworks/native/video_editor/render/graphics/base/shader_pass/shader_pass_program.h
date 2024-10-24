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

#ifndef OH_VEF_GRAPHICS_SHADER_PASS_PROGRAM_H
#define OH_VEF_GRAPHICS_SHADER_PASS_PROGRAM_H

#include <GLES3/gl3.h>
#include "render/graphics/base/math/render_matrix.h"
#include "render/graphics/base/math/render_vector.h"
#include "render/graphics/base/render_context.h"
#include "render_general_program.h"

namespace OHOS {
namespace Media {
class ShaderPassProgram {
public:
    ShaderPassProgram(RenderContext* context, const std::string& vertex, const std::string& fragment);
    ~ShaderPassProgram();

    void Bind();
    void Unbind();

    int GetAttributeLocation(std::string attributeName);

    int GetUniformLocation(std::string uniformName);

    void SetInt(std::string name, int value);

    void SetFloat(std::string name, float value);

    void SetVec2(std::string name, Vec2 value);

    void SetVec3(std::string name, Vec3 value);

    void SetVec4(std::string name, Vec4 value);

    void SetMat2(std::string name, Mat2x2 value);

    void SetMat3(std::string name, Mat3x3 value);

    void SetMat4(std::string name, Mat4x4 value);

    void BindTexture(std::string name, int unitId, int textureId, GLenum target = GL_TEXTURE_2D);

    void UnBindTexture(int unitId);

    std::shared_ptr<RenderGeneralProgram> GetShader();

private:
    std::shared_ptr<RenderGeneralProgram> shader_ = nullptr;
    RenderContext* context_ = nullptr;
    std::string vertexShaderCode_;
    std::string fragmentShaderCode_;
};
}
}

#endif
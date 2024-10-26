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

#ifndef OH_VEF_GRAPHICS_RENDER_PROGRAM_H
#define OH_VEF_GRAPHICS_RENDER_PROGRAM_H

#include "render/graphics/base/math/render_matrix.h"
#include "render/graphics/base/math/render_vector.h"
#include "render/graphics/base/render_context.h"
#include "render/graphics/base/render_object.h"

namespace OHOS {
namespace Media {
class RenderProgram : public RenderObject {
public:
    const static uint32_t INVALID_PROGRAM_NAME = 0;

public:
    explicit RenderProgram(RenderContext* m_context);
    ~RenderProgram() = default;
    void Bind();
    static void Unbind();
    void SetUniform(const std::string& name, float value);
    void SetUniform(const std::string& name, int32_t value);
    void SetUniform(const std::string& name, uint32_t value);
    void SetUniform(const std::string& name, const Vec2& value);
    void SetUniform(const std::string& name, const Vec3& value);
    void SetUniform(const std::string& name, const Vec4& value);
    void SetUniform(const std::string& name, const Mat2x2& value);
    void SetUniform(const std::string& name, const Mat3x3& value);
    void SetUniform(const std::string& name, const Mat4x4& value);

    uint32_t GetName();
    int32_t GetAttributeLocation(const std::string& name);
    int32_t GetUniformLocation(const std::string& name);

protected:
    uint32_t program_{ 0 };
    RenderContext* context_{ nullptr };
};
}
}

#endif
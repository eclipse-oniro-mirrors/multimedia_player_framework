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

#include <GLES3/gl3.h>
#include "render/graphics/base/math/math_utils.h"
#include "render_program.h"

namespace OHOS {
namespace Media {
RenderProgram::RenderProgram(RenderContext* context) : program_(0), context_(context) {}

void RenderProgram::SetUniform(const std::string& name, float value)
{
    glUniform1f(glGetUniformLocation(program_, name.c_str()), value);
}

void RenderProgram::SetUniform(const std::string& name, int32_t value)
{
    glUniform1i(glGetUniformLocation(program_, name.c_str()), value);
}

void RenderProgram::SetUniform(const std::string& name, uint32_t value)
{
    glUniform1ui(glGetUniformLocation(program_, name.c_str()), value);
}

void RenderProgram::SetUniform(const std::string& name, const Vec2& value)
{
    glUniform2f(glGetUniformLocation(program_, name.c_str()), value.x, value.y);
}

void RenderProgram::SetUniform(const std::string& name, const Vec3& value)
{
    glUniform3f(glGetUniformLocation(program_, name.c_str()), value.x, value.y, value.z);
}

void RenderProgram::SetUniform(const std::string& name, const Vec4& value)
{
    glUniform4f(glGetUniformLocation(program_, name.c_str()), value.x, value.y, value.z, value.w);
}

void RenderProgram::SetUniform(const std::string& name, const Mat2x2& value)
{
    glUniformMatrix2fv(glGetUniformLocation(program_, name.c_str()), 1, GL_FALSE,
        reinterpret_cast<const GLfloat*>(MathUtils::NativePtr(value)));
}

void RenderProgram::SetUniform(const std::string& name, const Mat3x3& value)
{
    glUniformMatrix3fv(glGetUniformLocation(program_, name.c_str()), 1, GL_FALSE,
        reinterpret_cast<const GLfloat*>(MathUtils::NativePtr(value)));
}

void RenderProgram::SetUniform(const std::string& name, const Mat4x4& value)
{
    glUniformMatrix4fv(glGetUniformLocation(program_, name.c_str()), 1, GL_FALSE,
        reinterpret_cast<const GLfloat*>(MathUtils::NativePtr(value)));
}

void RenderProgram::Bind()
{
    glUseProgram(program_);
}

void RenderProgram::Unbind()
{
    glUseProgram(INVALID_PROGRAM_NAME);
}

uint32_t RenderProgram::GetName()
{
    return program_;
}

int32_t RenderProgram::GetAttributeLocation(const std::string& name)
{
    return glGetAttribLocation(program_, name.c_str());
}

int32_t RenderProgram::GetUniformLocation(const std::string& name)
{
    return glGetUniformLocation(program_, name.c_str());
}
}
}
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

#include "shader_pass_program.h"

namespace OHOS {
namespace Media {
ShaderPassProgram::ShaderPassProgram(RenderContext* context, const std::string& vertex, const std::string& fragment)
{
    context_ = context;
    shader_ = std::make_shared<RenderGeneralProgram>(context, vertex.c_str(), fragment.c_str());
    shader_->Init();
    vertexShaderCode_ = vertex;
    fragmentShaderCode_ = fragment;
}

ShaderPassProgram::~ShaderPassProgram()
{
    if (shader_) {
        shader_->Release();
        shader_ = nullptr;
    }
}

void ShaderPassProgram::Bind()
{
    shader_->Bind();
}

void ShaderPassProgram::Unbind()
{
    shader_->Unbind();
}

int ShaderPassProgram::GetAttributeLocation(std::string attributeName)
{
    return shader_->GetAttributeLocation(attributeName.c_str());
}

int ShaderPassProgram::GetUniformLocation(std::string uniformName)
{
    return shader_->GetUniformLocation(uniformName.c_str());
}

void ShaderPassProgram::SetInt(std::string name, int value)
{
    shader_->SetUniform(name.c_str(), value);
}

void ShaderPassProgram::SetFloat(std::string name, float value)
{
    shader_->SetUniform(name.c_str(), value);
}

void ShaderPassProgram::SetVec2(std::string name, Vec2 value)
{
    shader_->SetUniform(name.c_str(), value);
}

void ShaderPassProgram::SetVec3(std::string name, Vec3 value)
{
    shader_->SetUniform(name.c_str(), value);
}

void ShaderPassProgram::SetVec4(std::string name, Vec4 value)
{
    shader_->SetUniform(name.c_str(), value);
}

void ShaderPassProgram::SetMat2(std::string name, Mat2x2 value)
{
    shader_->SetUniform(name.c_str(), value);
}

void ShaderPassProgram::SetMat3(std::string name, Mat3x3 value)
{
    shader_->SetUniform(name.c_str(), value);
}

void ShaderPassProgram::SetMat4(std::string name, Mat4x4 value)
{
    shader_->SetUniform(name.c_str(), value);
}

void ShaderPassProgram::BindTexture(std::string name, int unitId, int textureId, GLenum target)
{
    glActiveTexture(GL_TEXTURE0 + unitId);
    glBindTexture(target, textureId);
    glUniform1i(GetUniformLocation(name), unitId);
}

void ShaderPassProgram::UnBindTexture(int unitId)
{
    glActiveTexture(GL_TEXTURE0 + unitId);
    glBindTexture(GL_TEXTURE_2D, GL_NONE);
}

std::shared_ptr<RenderGeneralProgram> ShaderPassProgram::GetShader()
{
    return shader_;
}
}
}
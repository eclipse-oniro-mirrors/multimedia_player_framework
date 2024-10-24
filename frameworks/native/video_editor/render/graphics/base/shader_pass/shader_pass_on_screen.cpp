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

#include "render_mesh.h"
#include "shader_pass_on_screen.h"
#include "shader_pass_program.h"

namespace OHOS {
namespace Media {
constexpr const char* DEFAULT_VERTEX_SHADER_CODE = R"(attribute vec4 aPosition;\n
    attribute vec4 aTextureCoord;\n
    varying vec2 textureCoordinate;\n
    void main()\n
    {\n
        gl_Position = aPosition;\n
        textureCoordinate = aTextureCoord.xy;\n
    }\n)";

constexpr const char* DEFAULT_FRAGMENT_SHADER_CODE = R"(precision highp float;\n
    varying vec2 textureCoordinate;\n
    uniform sampler2D inputTexture;\n
    void main()\n
    {\n
       gl_FragColor = texture2D(inputTexture, textureCoordinate);\n
    }\n)";

ShaderPassOnScreen::ShaderPassOnScreen(RenderContext* context)
    : ShaderPass(context, DEFAULT_VERTEX_SHADER_CODE, DEFAULT_FRAGMENT_SHADER_CODE, DEFAULT_FLIP_VERTEX_DATA)
{
    renderEffectData_ = std::make_shared<RenderEffectData>();
}

ShaderPassOnScreen::~ShaderPassOnScreen() {}

RenderEffectDataPtr ShaderPassOnScreen::GetRenderEffectData()
{
    return renderEffectData_;
}

RenderTexturePtr ShaderPassOnScreen::Render()
{
    if (shader_ == nullptr) {
        shader_ = std::make_shared<ShaderPassProgram>(context_, vertexShaderCode_, fragmentShaderCode_);
    }
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glClearColor(0, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT);
    glViewport(0, 0, renderEffectData_->outputWidth_, renderEffectData_->outputHeight_);
    shader_->Bind();
    renderMesh_->Bind(shader_->GetShader());
    PreDraw();
    glDrawArrays(renderMesh_->primitiveType_, 0, renderMesh_->vertexNum_);
    PostDraw();
    shader_->Unbind();
    return nullptr;
}

void ShaderPassOnScreen::PreDraw()
{
    if (renderEffectData_->inputTexture_ != nullptr) {
        shader_->BindTexture("inputTexture", 0, renderEffectData_->inputTexture_->GetTextureId());
    }
}

void ShaderPassOnScreen::PostDraw()
{
    if (renderEffectData_->inputTexture_ != nullptr) {
        shader_->UnBindTexture(0);
        renderEffectData_->inputTexture_.reset();
    }
}
}
}
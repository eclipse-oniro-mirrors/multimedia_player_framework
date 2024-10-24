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
#include "shader_pass.h"
#include "shader_pass_program.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorRender"};
}
const std::vector<std::vector<float>> DEFAULT_VERTEX_DATA = { { -1.0f, -1.0f, 0.0f, 1.0f, -1.0f, 0.0f, -1.0f, 1.0f,
                                                                0.0f, 1.0f, 1.0f, 0.0f },
                                                              { 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f, 1.0f } };
const std::vector<std::vector<float>> DEFAULT_FLIP_VERTEX_DATA = { { -1.0f, -1.0f, 0.0f, 1.0f, -1.0f, 0.0f, -1.0f, 1.0f,
                                                                     0.0f, 1.0f, 1.0f, 0.0f },
                                                                   { 0.0f, 1.0f, 1.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0.0f } };
                                
                
ShaderPass::ShaderPass(RenderContext* context, std::string vertexShaderCode, std::string fragmentShaderCode,
    const std::vector<std::vector<float>>& meshData)
{
    context_ = context;
    fbo_ = GLUtils::CreateFramebuffer();
    vertexShaderCode_ = vertexShaderCode;
    fragmentShaderCode_ = fragmentShaderCode;

    renderMesh_ = std::make_shared<RenderMesh>(context, meshData);
}

ShaderPass::~ShaderPass()
{
    MEDIA_LOGD("~ShaderPass begin");

    if (fbo_ != 0) {
        GLUtils::DeleteFboOnly(fbo_);
    }
    MEDIA_LOGD("~ShaderPass end");
}

RenderTexturePtr ShaderPass::Render()
{
    if (shader_ == nullptr) {
        shader_ = std::make_shared<ShaderPassProgram>(context_, vertexShaderCode_, fragmentShaderCode_);
    }
    auto tex = std::make_shared<RenderTexture>(context_, renderEffectData_->outputWidth_,
        renderEffectData_->outputHeight_, GL_RGBA8);
    if (!tex->Init()) {
        MEDIA_LOGE("init RenderTexture object failed.");
        return nullptr;
    }
    glBindFramebuffer(GL_FRAMEBUFFER, fbo_);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tex->GetTextureId(), 0);
    glClearColor(0, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT);
    glViewport(0, 0, renderEffectData_->outputWidth_, renderEffectData_->outputHeight_);
    shader_->Bind();
    renderMesh_->Bind(shader_->GetShader());
    PreDraw();
    glDrawArrays(renderMesh_->primitiveType_, 0, renderMesh_->vertexNum_);
    PostDraw();
    shader_->Unbind();
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, 0, 0);
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    return tex;
}
}
}
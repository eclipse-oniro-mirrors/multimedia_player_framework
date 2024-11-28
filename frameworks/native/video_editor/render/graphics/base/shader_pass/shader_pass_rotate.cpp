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

#include "shader_pass_rotate.h"
#include "shader_pass.h"
#include "shader_pass_surface.h"
#include "render/graphics/graphics_render_engine.h"
#include "shader_pass_program.h"
#include "render_mesh.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorRender"};
}

constexpr const char* SURFACE_VERTEX_SHADER_CODE = R"(uniform mat4 uTexMatrix;
    attribute vec4 aPosition;
    attribute vec4 aTextureCoord;
    varying vec2 vTextureCoord;
    void main() {
        gl_Position = aPosition;
        vTextureCoord = (uTexMatrix * vec4(aTextureCoord.xy, 0.0, 1.0)).xy;
    }
    )";

constexpr const char* SURFACE_ROTATE_FRAGMENT_SHADER_CODE = R"(
    precision mediump float;
    varying vec2 vTextureCoord;
    uniform sampler2D sTexture;
    void main() {
        gl_FragColor = texture2D(sTexture, vTextureCoord);
    }
    )";

ShaderPassRotate::ShaderPassRotate(RenderContext* context)
    : ShaderPass(context, SURFACE_VERTEX_SHADER_CODE, SURFACE_ROTATE_FRAGMENT_SHADER_CODE, DEFAULT_VERTEX_DATA)
{
    renderEffectData_ = std::make_shared<SurfaceData>();
}

ShaderPassRotate::~ShaderPassRotate() {}

SurfaceDataPtr ShaderPassRotate::GetRenderEffectData()
{
    return std::static_pointer_cast<SurfaceData>(renderEffectData_);
}

void ShaderPassRotate::PreDraw()
{
    SurfaceDataPtr surfaceData = std::static_pointer_cast<SurfaceData>(renderEffectData_);
    if (shader_ == nullptr || surfaceData == nullptr) {
        MEDIA_LOGE("ShaderPassRotate::PreDraw failed because the shader or surfaceData is nullptr.");
        return;
    }
    if (surfaceData->inputTexture_ != nullptr) {
        shader_->BindTexture("sTexture", 0, surfaceData->inputTexture_->GetTextureId());
    }
    shader_->SetMat4("uTexMatrix", surfaceData->uTexMatrix);
}

void ShaderPassRotate::PostDraw()
{
    SurfaceDataPtr surfaceData = std::static_pointer_cast<SurfaceData>(renderEffectData_);
    if (surfaceData->inputTexture_ != nullptr) {
        shader_->UnBindTexture(0);
        surfaceData->inputTexture_.reset();
    }
}
}
}
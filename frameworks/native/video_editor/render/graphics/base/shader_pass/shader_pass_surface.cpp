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

#include "shader_pass_surface.h"
#include "shader_pass_program.h"

namespace OHOS {
namespace Media {
#ifndef GL_TEXTURE_EXTERNAL_OES
#define GL_TEXTURE_EXTERNAL_OES 0x8D65
#endif

constexpr const char* SURFACE_VERTEX_SHADER_CODE = "uniform mat4 uTexMatrix;\n"
    "attribute vec4 aPosition;\n"
    "attribute vec4 aTextureCoord;\n"
    "varying vec2 vTextureCoord;\n"
    "void main() {\n"
    "    gl_Position = aPosition;\n"
    "    vTextureCoord = (uTexMatrix * vec4(aTextureCoord.xy, 0.0, 1.0)).xy;\n"
    "}\n";

constexpr const char* SURFACE_FRAGMENT_SHADER_CODE = "#extension GL_OES_EGL_image_external : require\n"
    "precision mediump float;\n"
    "varying vec2 vTextureCoord;\n"
    "uniform samplerExternalOES sTexture;\n"
    "void main() {\n"
    "    gl_FragColor = texture2D(sTexture, vTextureCoord);\n"
    "}\n";

ShaderPassSurface::ShaderPassSurface(RenderContext* context)
    : ShaderPass(context, SURFACE_VERTEX_SHADER_CODE, SURFACE_FRAGMENT_SHADER_CODE, DEFAULT_VERTEX_DATA)
{
    renderEffectData_ = std::make_shared<SurfaceData>();
}

ShaderPassSurface::~ShaderPassSurface() {}

SurfaceDataPtr ShaderPassSurface::GetRenderEffectData()
{
    return std::static_pointer_cast<SurfaceData>(renderEffectData_);
}

void ShaderPassSurface::PreDraw()
{
    SurfaceDataPtr surfaceData = std::static_pointer_cast<SurfaceData>(renderEffectData_);
    if (shader_) {
        shader_->BindTexture("sTexture", 0, surfaceData->nativeTexId, GL_TEXTURE_EXTERNAL_OES);
        shader_->SetMat4("uTexMatrix", surfaceData->uTexMatrix);
    }
}

void ShaderPassSurface::PostDraw()
{
    SurfaceDataPtr surfaceData = std::static_pointer_cast<SurfaceData>(renderEffectData_);
    if (surfaceData->inputTexture_ != nullptr) {
        shader_->UnBindTexture(0);
        surfaceData->inputTexture_.reset();
    }
}
}
}
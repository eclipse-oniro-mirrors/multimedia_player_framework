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

#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <EGL/eglext.h>
#include <GLES2/gl2ext.h>
#include "image_effect_render.h"
#include "native_buffer.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorRender"};
}
constexpr char SET_INPUT_TEXTURE[] = "INPUT_TEX";
constexpr char SET_OUTPUT_TEXTURE[] = "OUT_TEX";
constexpr char SET_TEXTURE_WIDTH[] = "INPUT_WIDTH";
constexpr char SET_TEXTURE_HEIGHT[] = "INPUT_HEIGHT";

#ifdef IMAGE_EFFECT_SUPPORT
ImageEffectRender::ImageEffectRender(const std::shared_ptr<OH_ImageEffect>& imageEffect)
    : RenderObject(), imageEffect_(imageEffect)
{
    MEDIA_LOGD("construct.");
    auto initResult = Init();
    if (initResult == false) {
        MEDIA_LOGE("init image effect render failed.");
    }
    SetReady(initResult);
    MEDIA_LOGD("construct finish.");
}
#else
ImageEffectRender::ImageEffectRender()
    : RenderObject()
{
}
#endif

ImageEffectRender::~ImageEffectRender()
{
    MEDIA_LOGD("destruct.");
    Release();
    MEDIA_LOGD("destruct finish.");
}

bool ImageEffectRender::Init()
{
    auto initEffectFilterResult = InitEffectFilter();
    if (initEffectFilterResult != VEFError::ERR_OK) {
        MEDIA_LOGE("init effect filter failed with error: %{public}d.", initEffectFilterResult);
        return false;
    }
    return true;
}

bool ImageEffectRender::Release()
{
    SetReady(false);

    return true;
}

VEFError ImageEffectRender::InitEffectFilter()
{
#ifdef IMAGE_EFFECT_SUPPORT
    if (effectFilter_ == nullptr) {
        int32_t filterCount = OH_ImageEffect_GetFilterCount(imageEffect_.get());
        if (filterCount <= 0) {
            MEDIA_LOGE("no filter.");
            return VEFError::ERR_INTERNAL_ERROR;
        }
        effectFilter_ = OH_ImageEffect_GetFilter(imageEffect_.get(), 0);
        if (effectFilter_ == nullptr) {
            MEDIA_LOGE("cannot get filter.");
            return VEFError::ERR_INTERNAL_ERROR;
        }
    }
    return VEFError::ERR_OK;
#else
    return VEFError::ERR_INTERNAL_ERROR;
#endif
}

RenderTexturePtr ImageEffectRender::Render(
    RenderContext *context,
    RenderSurface* surface,
    const RenderTexturePtr& inputRenderTexture,
    const int32_t colorRange)
{
#ifdef IMAGE_EFFECT_SUPPORT
    if (!IsReady()) {
        MEDIA_LOGE("image effect render is not ready.");
        return inputRenderTexture;
    }

    GLsizei width = inputRenderTexture->Width();
    GLsizei height = inputRenderTexture->Height();
    colorRange_ = colorRange;

    auto tex = std::make_shared<RenderTexture>(context, width, height, GL_RGBA8);
    if (!tex->Init()) {
        MEDIA_LOGE("init RenderTexture object failed.");
        return inputRenderTexture;
    }
    ImageEffect_Any inputTexVal = {
        .dataType = ImageEffect_DataType::EFFECT_DATA_TYPE_INT32,
        .dataValue.int32Value = (int32_t) inputRenderTexture->GetTextureId()
    };
    OH_EffectFilter_SetValue(effectFilter_, SET_INPUT_TEXTURE, &inputTexVal);

    ImageEffect_Any outputTexVal = {
        .dataType = ImageEffect_DataType::EFFECT_DATA_TYPE_INT32,
        .dataValue.int32Value = (int32_t) tex->GetTextureId()
    };
    OH_EffectFilter_SetValue(effectFilter_, SET_INPUT_TEXTURE, &outputTexVal);

    ImageEffect_Any widthVal = {
        .dataType = ImageEffect_DataType::EFFECT_DATA_TYPE_INT32,
        .dataValue.int32Value = (int32_t) width
    };
    OH_EffectFilter_SetValue(effectFilter_, SET_INPUT_TEXTURE, &widthVal);

    ImageEffect_Any heightVal = {
        .dataType = ImageEffect_DataType::EFFECT_DATA_TYPE_INT32,
        .dataValue.int32Value = (int32_t) height
    };
    OH_EffectFilter_SetValue(effectFilter_, SET_INPUT_TEXTURE, &heightVal);

    OH_EffectFilter_Render(effectFilter_, nullptr, nullptr);
    return tex;
#else
    return inputRenderTexture
#endif
}
}
}
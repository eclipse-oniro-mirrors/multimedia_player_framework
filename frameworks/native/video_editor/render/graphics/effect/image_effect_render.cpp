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

ImageEffectRender::~ImageEffectRender()
{
    MEDIA_LOGD("destruct.");
    Release();
    MEDIA_LOGD("destruct finish.");
}

bool ImageEffectRender::Init()
{
    tempTexForEffect_ = GLUtils::CreateTexture2DNoStorage(GL_LINEAR, GL_LINEAR, GL_CLAMP_TO_EDGE, GL_CLAMP_TO_EDGE);
    if (tempTexForEffect_ == GL_NONE) {
        MEDIA_LOGE("Create input texture failed.");
        return false;
    }
    return true;
}

bool ImageEffectRender::Release()
{
    if (tempTexForEffect_ != GL_NONE) {
        GLUtils::DeleteTexture(tempTexForEffect_);
        tempTexForEffect_ = GL_NONE;
    }

    ReleaseNativeBuffer();
    return true;
}

VEFError ImageEffectRender::InitNativeBuffer(int32_t width, int32_t height)
{
    VEFError error = VEFError::ERR_OK;
    if (nativeBuffer_ == nullptr) {
        error = CreateNativeBuffer(width, height, tempTexForEffect_, &nativeBuffer_, &nativeWindowBuffer_);
        if (error != VEFError::ERR_OK) {
            MEDIA_LOGE("Create native for input failed.");
            ReleaseNativeBuffer();
            return error;
        }
        ImageEffect_ErrorCode errorCode = OH_ImageEffect_SetInputNativeBuffer(imageEffect_.get(), nativeBuffer_);
        if (errorCode != ImageEffect_ErrorCode::EFFECT_SUCCESS) {
            MEDIA_LOGE("OH_ImageEffect_SetInputNativeBuffer failed : %{public}d.", errorCode);
            error = VEFError::ERR_INTERNAL_ERROR;
            ReleaseNativeBuffer();
            return error;
        }
    }
    return error;
}

void ImageEffectRender::ReleaseNativeBuffer()
{
    if (nativeWindowBuffer_) {
        OH_NativeWindow_DestroyNativeWindowBuffer(nativeWindowBuffer_);
        nativeWindowBuffer_ = nullptr;
    }
    if (nativeBuffer_) {
        OH_NativeBuffer_Unreference(nativeBuffer_);
        nativeBuffer_ = nullptr;
    }
}

RenderTexturePtr ImageEffectRender::Render(
    RenderContext *context,
    RenderSurface* surface,
    const RenderTexturePtr& inputRenderTexture,
    const int32_t colorRange)
{
    if (!IsReady()) {
        MEDIA_LOGE("image effect render is not ready.");
        return inputRenderTexture;
    }

    GLsizei width = inputRenderTexture->Width();
    GLsizei height = inputRenderTexture->Height();
    colorRange_ = colorRange;
    auto initNativeResult = InitNativeBuffer(width, height);
    if (initNativeResult != VEFError::ERR_OK) {
        MEDIA_LOGE("init native buffer failed with error: %{public}d.", initNativeResult);
        return inputRenderTexture;
    }

    GLUtils::CopyTexture(inputRenderTexture->GetTextureId(), tempTexForEffect_, width, height);
    GLUtils::CheckError(__FILE_NAME__, __LINE__);

    auto errorCode = OH_ImageEffect_Start(imageEffect_.get());
    if (errorCode != ImageEffect_ErrorCode::EFFECT_SUCCESS) {
        MEDIA_LOGE("OH_ImageEffect_Start failed: %{public}d.", errorCode);
    }

    context->MakeCurrent(surface);

    auto tex = std::make_shared<RenderTexture>(context, width, height, GL_RGBA8);
    if (!tex->Init()) {
        MEDIA_LOGE("init RenderTexture object failed.");
        return inputRenderTexture;
    }

    GLUtils::CopyTexture(tempTexForEffect_, tex->GetTextureId(), width, height);

    MEDIA_LOGD("ImageEffectRender::Render finish.");
    return tex;
}

VEFError ImageEffectRender::CreateNativeBuffer(int32_t width, int32_t height, GLuint textureId,
    OH_NativeBuffer** nativeBuffer, OHNativeWindowBuffer** nativeWindowBuffer)
{
    OH_NativeBuffer_Config config {.width = static_cast<int32_t>(width),
                                   .height = static_cast<int32_t>(height),
                                   .format = NATIVEBUFFER_PIXEL_FMT_RGBA_8888,
                                   .usage = NATIVEBUFFER_USAGE_CPU_READ |
                                              NATIVEBUFFER_USAGE_CPU_WRITE |
                                              NATIVEBUFFER_USAGE_MEM_DMA};
    OH_NativeBuffer *nativeBufferPtr = OH_NativeBuffer_Alloc(&config);
    OH_NativeBuffer_ColorSpace colorSpace = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT;
    if (colorRange_ == 1)
    {
        colorSpace = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_FULL;
    }
    OHNativeWindowBuffer* nativeWindowBufferPtr =
        OH_NativeWindow_CreateNativeWindowBufferFromNativeBuffer(nativeBufferPtr);
    OH_NativeBuffer_SetColorSpace(nativeBufferPtr, colorSpace);

    EGLint attrs[] = {EGL_IMAGE_PRESERVED, EGL_TRUE, EGL_NONE};
    EGLDisplay dsp = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    static auto eglCreateImageKHRFunc =
        reinterpret_cast<PFNEGLCREATEIMAGEKHRPROC>(eglGetProcAddress("eglCreateImageKHR"));
    EGLImageKHR img =
        eglCreateImageKHRFunc(dsp, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_OHOS, nativeWindowBufferPtr, attrs);
    if (img == EGL_NO_IMAGE_KHR) {
        MEDIA_LOGE("eglCreateImageKHRFunc failed.");
        OH_NativeWindow_DestroyNativeWindowBuffer(nativeWindowBufferPtr);
        OH_NativeBuffer_Unreference(nativeBufferPtr);
        return VEFError::ERR_INTERNAL_ERROR;
    }

    glBindTexture(GL_TEXTURE_2D, textureId);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);

    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    static auto glEGLImageTargetTexture2DOESFunc =
        reinterpret_cast<PFNGLEGLIMAGETARGETTEXTURE2DOESPROC>(
            eglGetProcAddress("glEGLImageTargetTexture2DOES"));
    glEGLImageTargetTexture2DOESFunc(GL_TEXTURE_2D, static_cast<GLeglImageOES>(img));

    *nativeBuffer = nativeBufferPtr;
    *nativeWindowBuffer = nativeWindowBufferPtr;
    MEDIA_LOGD("glEGLImageTargetTexture2DOESFunc finish.");
    return VEFError::ERR_OK;
}
}
}
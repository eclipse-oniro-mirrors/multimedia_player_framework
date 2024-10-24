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

#include "render_surface.h"
#include <EGL/eglext.h>

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorRender"};
}

RenderSurface::RenderSurface(std::string tag)
    : display_(EGL_NO_DISPLAY), config_(EGL_NO_CONFIG_KHR), surface_(EGL_NO_SURFACE) {}

RenderSurface::~RenderSurface() {
    Release();
}

void RenderSurface::SetAttrib(const RenderAttribute& attrib)
{
    attribute_ = attrib;
}

RenderAttribute RenderSurface::GetAttrib()
{
    return attribute_;
}

bool RenderSurface::Create(OHNativeWindow* window)
{
    EGLint retNum = 0;
    display_ = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    std::vector<EGLint> attributeList = attribute_.ToEglAttribList();
    EGLBoolean ret = eglChooseConfig(display_, attributeList.data(), &config_, 1, &retNum);
    if (ret != EGL_TRUE) {
        EGLint error = eglGetError();
        MEDIA_LOGE("[Render] RenderSurface Init ON Fail 0! Code: %{public}d", error);
        return false;
    }
    EGLint surfaceAttribs[] = {
        EGL_NONE
    };
    EGLNativeWindowType mEglWindow = reinterpret_cast<EGLNativeWindowType>(window);

    surface_ = eglCreateWindowSurface(display_, config_, mEglWindow, surfaceAttribs);
    if (surface_ == EGL_NO_SURFACE) {
        EGLint error = eglGetError();
        MEDIA_LOGE("[Render] RenderSurface Init ON Fail 1! Code: %{public}d", error);
        return false;
    }
    SetReady(true);
    return true;
}

bool RenderSurface::Init()
{
    EGLint retNum = 0;
    display_ = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    std::vector<EGLint> attributeList = attribute_.ToEglAttribList();
    EGLBoolean ret = eglChooseConfig(display_, attributeList.data(), &config_, 1, &retNum);
    if (ret != EGL_TRUE) {
        EGLint error = eglGetError();
        MEDIA_LOGE("[Render] RenderSurface Init OFF Fail 0! Code: %{public}d", error);
        return false;
    }
    EGLint surfaceAttribs[] = {
        EGL_NONE
    };
    surface_ = eglCreatePbufferSurface(display_, config_, surfaceAttribs);
    if (surface_ == EGL_NO_SURFACE) {
        EGLint error = eglGetError();
        MEDIA_LOGE("[Render] RenderSurface Init OFF Fail 1! Code: %{public}d", error);
        return false;
    }
    SetReady(true);
    return true;
}

bool RenderSurface::Release()
{
    if (IsReady()) {
        EGLBoolean ret = eglDestroySurface(display_, surface_);
        if (ret != EGL_TRUE) {
            EGLint error = eglGetError();
            MEDIA_LOGE("[Render] RenderSurface Release Fail 0! Code: %{public}d", error);
            return false;
        }
        SetReady(false);
    }
    return true;
}

void* RenderSurface::GetRawSurface() const
{
    return (void*)surface_;
}
}
}
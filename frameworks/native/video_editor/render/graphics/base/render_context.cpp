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

#include "render_context.h"
#include <EGL/eglext.h>

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorRender"};
}
RenderContext::RenderContext() : display_(EGL_NO_DISPLAY), context_(EGL_NO_CONTEXT) {}

RenderContext::~RenderContext() {}

bool RenderContext::Create(RenderContext* sharedContext)
{
    display_ = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display_ == EGL_NO_DISPLAY) {
        MEDIA_LOGE("RenderContext: unable to get EGL display.");
        return false;
    }

    int attribList[] = { EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE };
    context_ = eglCreateContext(display_, EGL_NO_CONFIG_KHR, sharedContext, attribList);
    if (context_ == nullptr) {
        MEDIA_LOGE("RenderContext: unable to create egl context");
        return false;
    }

    eglSwapInterval(display_, 0);

    SetReady(true);
    return true;
}

bool RenderContext::Init()
{
    return Create(nullptr);
}

bool RenderContext::Release()
{
    if (IsReady()) {
        EGLBoolean ret = eglDestroyContext(display_, context_);
        if (ret != EGL_TRUE) {
            EGLint error = eglGetError();
            MEDIA_LOGE("[Render] RenderContext Release Fail 0! Code: %{public}d", error);
            return false;
        }

        SetReady(false);
    }

    return true;
}

bool RenderContext::MakeCurrent(const RenderSurface* surface)
{
    if (!IsReady()) {
        MEDIA_LOGE("[Render] MakeCurrent Fail 0!");
        return false;
    }

    EGLSurface rawSurface = EGL_NO_SURFACE;
    if (surface) {
        rawSurface = static_cast<EGLSurface>(surface->GetRawSurface());
    }

    EGLBoolean ret = eglMakeCurrent(display_, rawSurface, rawSurface, context_);
    if (ret != EGL_TRUE) {
        EGLint error = eglGetError();
        MEDIA_LOGE("[Render] MakeCurrent Fail 1! Code: %{public}d", error);
        return false;
    }
    return true;
}

bool RenderContext::ReleaseCurrent()
{
    if (!IsReady()) {
        MEDIA_LOGE("[Render] ReleaseCurrent Fail 0!");
        return false;
    }

    EGLBoolean ret = eglMakeCurrent(display_, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    if (ret != EGL_TRUE) {
        EGLint error = eglGetError();
        MEDIA_LOGE("[Render] ReleaseCurrent Fail 1! Code: %{public}d", error);
        return false;
    }
    return true;
}

bool RenderContext::SwapBuffers(const RenderSurface* surface)
{
    if (!IsReady()) {
        MEDIA_LOGE("[Render] SwapBuffer Fail 0!");
        return false;
    }
    if (surface == nullptr) {
        MEDIA_LOGE("[Render] surface is null!");
        return false;
    }
    EGLSurface rawSurface = static_cast<EGLSurface>(surface->GetRawSurface());
    EGLBoolean ret = eglSwapBuffers(display_, rawSurface);
    if (ret != EGL_TRUE) {
        EGLint error = eglGetError();
        MEDIA_LOGE("[Render] SwapBuffer Fail 1! Code: %{public}d", error);
        return false;
    }
    return true;
}
}
}
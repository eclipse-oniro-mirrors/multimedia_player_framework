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

#include "native_avcodec_base.h"
#include <sstream>
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <GLES3/gl31.h>
#include "external_window.h"
#include "native_averrors.h"
#include "graphics_render_engine_impl.h"
#include "render/graphics/base/gl_utils.h"
#include "render/graphics/base/render_context.h"
#include "render/graphics/base/render_surface.h"
#include "render/graphics/base/task/render_task.h"
#include "render/graphics/base/math/render_matrix.h"
#include "render/graphics/base/shader_pass/shader_pass_surface.h"
#include "render/graphics/base/shader_pass/shader_pass_on_screen.h"
#include "render/graphics/effect/image_effect_render.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "Render"};
}
GraphicsRenderEngineImpl::GraphicsRenderEngineImpl(uint64_t id) : id_(id)
{
    MEDIA_LOGD("construct.");
}

GraphicsRenderEngineImpl::~GraphicsRenderEngineImpl()
{
    MEDIA_LOGD("destroy begin.");
    Destroy();
}

void GraphicsRenderEngineImpl::Destroy()
{
    std::lock_guard<std::recursive_mutex> guard(renderMutex_);

    if (!ready_) {
        MEDIA_LOGW("graphics render engine[id=%{public}" PRIu64 "] is not ready, need not destroy.", id_);
        return;
    }
    ready_ = false;
    if (renderThread_) {
        auto task =
            std::make_shared<RenderTask<>>([this]() { this->ReleaseThread(); }, COMMON_TASK_TAG, RequestTaskId());
        renderThread_->ClearTaskQueue();
        renderThread_->AddTask(task);
        task->Wait();
        delete renderThread_;
        renderThread_ = nullptr;
    }
    MEDIA_LOGI("[Render] Engine %{public}" PRIu64 " destroy end!", id_);
}

VEFError GraphicsRenderEngineImpl::Init(OHNativeWindow* outputWindow)
{
    MEDIA_LOGI("init graphics engine.");
    if (ready_) {
        MEDIA_LOGW("[Render] graphics engine [id = %{public}llu] has been initialized, please do not initialize again.",
            id_);
        return VEFError::ERR_OK;
    }

    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (!eglInitialize(display, nullptr, nullptr)) {
        MEDIA_LOGE("unable to initialize display");
        return VEFError::ERR_INTERNAL_ERROR;
    }
    MEDIA_LOGI("eglInitialize initialize finish");

    VEFError ret = InitExportEngine(outputWindow);
    if (ret != VEFError::ERR_OK) {
        MEDIA_LOGE("init export engine failed with error: %{public}d.", ret);
        return ret;
    }

    auto func = []() {};
    renderThread_ = new (std::nothrow) RenderThread<>(RENDER_QUEUE_SIZE, func);
    if (renderThread_ == nullptr) {
        MEDIA_LOGE("create render thread failed.");
        return VEFError::ERR_INTERNAL_ERROR;
    }

    renderThread_->Start();
    VEFError error = VEFError::ERR_OK;
    auto task = std::make_shared<RenderTask<>>(
        [this, &error]() {
            error = this->InitThread();
            if (error != VEFError::ERR_OK) {
                return;
            }
            error = this->InitSurfaceTexture();
            if (error != VEFError::ERR_OK) {
                return;
            }

            shaderPassSurface_ = std::make_shared<ShaderPassSurface>(context_.get());
            shaderPassOnScreen_ = std::make_shared<ShaderPassOnScreen>(context_.get());
            shaderPassRotate_ = std::make_shared<ShaderPassRotate>(context_.get());
            ready_ = true;
        },
        COMMON_TASK_TAG, RequestTaskId());
    renderThread_->AddTask(task);
    task->Wait();

    MEDIA_LOGI("initEnv finish");
    return VEFError::ERR_OK;
}

VEFError GraphicsRenderEngineImpl::StartRender()
{
    MEDIA_LOGI("StartRender engine");
    return VEFError::ERR_OK;
}

VEFError GraphicsRenderEngineImpl::UnInit()
{
    if (renderThread_ != nullptr) {
        delete renderThread_;
        renderThread_ = nullptr;
        MEDIA_LOGI("uninit graphics engine");
    }
    return VEFError::ERR_OK;
}

VEFError GraphicsRenderEngineImpl::StopRender()
{
    MEDIA_LOGI("StopRender engine");
    if (ready_) {
        renderThread_->ClearTaskQueue();
        auto task =
            std::make_shared<RenderTask<>>([this]() { this->ReleaseThread(); }, COMMON_TASK_TAG, RequestTaskId());
        renderThread_->AddTask(task);
        task->Wait();
    }
    return VEFError::ERR_OK;
}

VEFError GraphicsRenderEngineImpl::InitExportEngine(OHNativeWindow* window)
{
    MEDIA_LOGI("[Render] InitExportEngine %{public}" PRIu64 "begin", id_);
    if (window == nullptr) {
        MEDIA_LOGE("init export engine failed, the window is nullptr.");
        return VEFError::ERR_INVALID_PARAM;
    }

    exportWindow_ = window;
    surface_ = new (std::nothrow) RenderSurface(std::string());
    if (surface_ == nullptr) {
        MEDIA_LOGE("create RenderSurface object failed.");
        return VEFError::ERR_OOM;
    }

    surface_->SetAttrib(attribute_);
    surface_->Create(window);

    MEDIA_LOGI("[Render] InitExportEngine %{public}" PRIu64 "success", id_);
    return VEFError::ERR_OK;
}

std::string GraphicsRenderEngineImpl::GetThreadId() const
{
    std::ostringstream stream;
    stream << std::this_thread::get_id();
    return stream.str();
}

VEFError GraphicsRenderEngineImpl::InitThread()
{
    std::string threadID = GetThreadId();
    MEDIA_LOGI("init render thread [%{public}s].", threadID.c_str());

    auto context = std::make_shared<RenderContext>();
    if (!context->Init()) {
        MEDIA_LOGE("init render context failed");
        return VEFError::ERR_INTERNAL_ERROR;
    }
    if (!context->MakeCurrent(surface_)) {
        MEDIA_LOGE("make egl context to current context failed");
        return VEFError::ERR_INTERNAL_ERROR;
    }
    context_ = context;
    MEDIA_LOGI("init render thread [%{public}s] success.", threadID.c_str());
    return VEFError::ERR_OK;
}

void GraphicsRenderEngineImpl::ReleaseThread()
{
    std::string threadId = GetThreadId();
    MEDIA_LOGD("ReleaseThread: %{public}s", threadId.c_str());
}

uint64_t GraphicsRenderEngineImpl::RequestTaskId()
{
    return currentTaskId_.fetch_add(1);
}

VEFError GraphicsRenderEngineImpl::InitSurfaceTexture()
{
    MEDIA_LOGI("init render surface texture.");
    VEFError result = VEFError::ERR_INTERNAL_ERROR;
    GLuint oesTexId = GL_NONE;
    do {
        auto surfaceTexture = std::make_shared<SurfaceTexture>();
        if (!context_->MakeCurrent(surface_)) {
            MEDIA_LOGE("make egl context to current context failed.");
            break;
        }
        oesTexId = GLUtils::CreateTexNoStorage(GL_TEXTURE_EXTERNAL_OES);
        if (oesTexId == GL_NONE) {
            MEDIA_LOGE("create oes texture object failed.");
            break;
        }
        surfaceTexture->nativeTexId_ = oesTexId;
        auto nativeImage = OH_NativeImage_Create(oesTexId, GL_TEXTURE_EXTERNAL_OES);
        if (nativeImage == nullptr) {
            MEDIA_LOGE("create nativeImage object failed.");
            break;
        }
        surfaceTexture->nativeImage_ =
            std::shared_ptr<OH_NativeImage>(nativeImage, [](OH_NativeImage* image) { OH_NativeImage_Destroy(&image); });
        surfaceTexture->nativeWindow_ = OH_NativeImage_AcquireNativeWindow(surfaceTexture->nativeImage_.get());
        if (surfaceTexture->nativeWindow_ == nullptr) {
            MEDIA_LOGE("OH_NativeImage_AcquireNativeWindow failed.");
            break;
        }
        OH_OnFrameAvailableListener listener;
        listener.context = surfaceTexture.get();
        listener.onFrameAvailable = SurfaceTexture::OnFrameAvailable;
        int32_t error = OH_NativeImage_SetOnFrameAvailableListener(surfaceTexture->nativeImage_.get(), listener);
        if (error != 0) {
            MEDIA_LOGE("OH_NativeImage_SetOnFrameAvailableListener failed with error:%{public}d.", error);
            break;
        }
        surfaceTexture_ = surfaceTexture;
        result = VEFError::ERR_OK;
        MEDIA_LOGI("init render surface texture success.");
    } while (false);
    if (result != VEFError::ERR_OK) {
        GLUtils::DeleteTexture(oesTexId);
    }
    return result;
}

OHNativeWindow* GraphicsRenderEngineImpl::GetInputWindow()
{
    if (surfaceTexture_ != nullptr) {
        return surfaceTexture_->nativeWindow_;
    }
    return nullptr;
}

VEFError GraphicsRenderEngineImpl::Render(uint64_t index, const std::shared_ptr<GraphicsRenderInfo>& effectInfo,
    const RenderResultCallback& cb)
{
    std::lock_guard<std::recursive_mutex> guard(renderMutex_);
    if (ready_) {
        MEDIA_LOGD("render frame[index = %{public}" PRIu64 "]", index);
    } else {
        MEDIA_LOGE("render engine not ready render frame[index = %{public}" PRIu64 "]failed", index);
        return VEFError::ERR_INTERNAL_ERROR;
    }
    auto taskId = RequestTaskId();
    auto launchTime = std::chrono::high_resolution_clock::now();
    auto task = std::make_shared<RenderTask<>>(
        [this, taskId, launchTime, index, effectInfo, cb]() {
            auto beginTime = std::chrono::high_resolution_clock::now();
            this->context_->MakeCurrent(surface_);
            auto renderTexture = this->RenderFrame(effectInfo);
            auto renderEndTime = std::chrono::high_resolution_clock::now();
            this->DrawFrame(index, renderTexture);
            auto drawEndtime = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> queueDelay = beginTime - launchTime;
            std::chrono::duration<double, std::milli> renderTime = renderEndTime - beginTime;
            std::chrono::duration<double, std::milli> drawtime = drawEndtime - renderEndTime;
            MEDIA_LOGD("renderTime: %{public}lf frawTime: %{public}lf,"
                " queueDelay: %{public}lf, TaskId: %{public}" PRIu64 ","
                "ExternId:  %{public}" PRIu64 ".", renderTime.count(), drawtime.count(),
                queueDelay.count(), taskId, index);
            cb(GraphicsRenderResult::SUCCESS);
        },
        EXPORT_TASK_TAG, taskId);

    renderThread_->AddTask(task);
    return VEFError::ERR_OK;
}

RenderTexturePtr GraphicsRenderEngineImpl::RenderFrame(const std::shared_ptr<GraphicsRenderInfo>& graphicsRenderInfo)
{
    surfaceTexture_->AwaitNativeImage();
    OH_NativeImage_UpdateSurfaceImage(surfaceTexture_->nativeImage_.get());
    GLint bufferW = -1;
    GLint bufferH = -1;
    glBindTexture(GL_TEXTURE_EXTERNAL_OES, surfaceTexture_->nativeTexId_);
    glGetTexLevelParameteriv(GL_TEXTURE_EXTERNAL_OES, 0, GL_TEXTURE_WIDTH, &bufferW);
    glGetTexLevelParameteriv(GL_TEXTURE_EXTERNAL_OES, 0, GL_TEXTURE_HEIGHT, &bufferH);
    glBindTexture(GL_TEXTURE_EXTERNAL_OES, 0);
    int32_t rotation = graphicsRenderInfo->rotation;
    Mat4x4 matrix = GLUtils::GetOesSamplingMatrix({ bufferW, bufferH }, { bufferW, bufferH }, rotation, false);
    SurfaceDataPtr surfaceData = shaderPassSurface_->GetRenderEffectData();
    surfaceData->nativeTexId = surfaceTexture_->nativeTexId_;
    surfaceData->uTexMatrix = matrix;
    const int32_t rotation90 = 90;
    const int32_t rotation270 = 270;
    if (rotation == rotation90 || rotation == rotation270) {
        surfaceData->outputWidth_ = bufferH;
        surfaceData->outputHeight_ = bufferW;
    } else {
        surfaceData->outputWidth_ = bufferW;
        surfaceData->outputHeight_ = bufferH;
    }
    auto outputRenderTexture = shaderPassSurface_->Render();
    outputRenderTexture = RenderEffects(outputRenderTexture, graphicsRenderInfo);
    if (rotation != 0) {
        Mat4x4 rotateMatrix = GLUtils::GetOesSamplingMatrix(
            {bufferW, bufferH},
            { bufferW, bufferH },
            -rotation,
            false);
        SurfaceDataPtr rotateSurfaceData = shaderPassRotate_->GetRenderEffectData();
        rotateSurfaceData->inputTexture_ = outputRenderTexture;
        rotateSurfaceData->outputWidth_ = bufferW;
        rotateSurfaceData->outputHeight_ = bufferH;
        rotateSurfaceData->uTexMatrix = rotateMatrix;
        auto outputTexture = shaderPassRotate_->Render();
        return outputTexture;
    } else {
        return outputRenderTexture;
    }
}

RenderTexturePtr GraphicsRenderEngineImpl::RenderEffects(const RenderTexturePtr& inputTexture,
    const std::shared_ptr<GraphicsRenderInfo>& graphicsRenderInfo)
{
    if (graphicsRenderInfo == nullptr) {
        MEDIA_LOGD("renderInfo is nullptr, not need render effect.");
        return inputTexture;
    }
    int32_t colorRange = graphicsRenderInfo->colorRange_;
    auto outputRenderTexture = inputTexture;
    for (const auto& effectInfo : graphicsRenderInfo->effectInfoList_) {
        if (effectInfo->type != EffectType::IMAGE_EFFECT) {
            MEDIA_LOGE("effectType [%{public}d] is not supported.", effectInfo->type);
            continue;
        }
        auto it = imageEffectRenderList_.find(effectInfo->id);
        if (it != imageEffectRenderList_.end()) {
            outputRenderTexture = it->second->Render(context_.get(), surface_, outputRenderTexture, colorRange);
        } else {
            auto imageEffectRender = std::make_shared<ImageEffectRender>(effectInfo->imageEffect);
            imageEffectRenderList_[effectInfo->id] = imageEffectRender;
            outputRenderTexture = imageEffectRender->Render(context_.get(), surface_, outputRenderTexture, colorRange);
        }
    }

    return outputRenderTexture;
}

void GraphicsRenderEngineImpl::DrawFrame(uint64_t pts, const RenderTexturePtr& renderTexture)
{
    auto retCode = OH_NativeWindow_NativeWindowHandleOpt(exportWindow_, SET_UI_TIMESTAMP, pts);
    if (retCode != AV_ERR_OK) {
        MEDIA_LOGE("set native window opt faild, retcode = %{public}d", retCode);
    }
    RenderEffectDataPtr renderEffectData = shaderPassOnScreen_->GetRenderEffectData();
    renderEffectData->inputTexture_ = renderTexture;
    renderEffectData->outputWidth_ = renderTexture->Width();
    renderEffectData->outputHeight_ = renderTexture->Height();
    shaderPassOnScreen_->Render();
    context_->SwapBuffers(surface_);
    renderTexture->Release();
}
}
}
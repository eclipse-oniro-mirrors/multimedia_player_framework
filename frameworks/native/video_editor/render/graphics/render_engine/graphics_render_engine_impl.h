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

#ifndef OH_VEF_GRAPHICS_RENDER_ENGINE_H
#define OH_VEF_GRAPHICS_RENDER_ENGINE_H

#include <GLES3/gl3.h>
#include "native_image.h"
#include "render/graphics/base/render_attribute.h"
#include "render/graphics/base/render_context.h"
#include "render/graphics/base/render_surface.h"
#include "render/graphics/base/shader_pass/shader_pass_rotate.h"
#include "render/graphics/base/shader_pass/shader_pass_surface.h"
#include "render/graphics/base/shader_pass/shader_pass_on_screen.h"
#include "render/graphics/effect/image_effect_render.h"
#include "render/graphics/base/surface_texture.h"
#include "render/graphics/base/worker/render_work.h"
#include "render/graphics/graphics_render_engine.h"

namespace OHOS {
namespace Media {
class GraphicsRenderEngineImpl : public IGraphicsRenderEngine {
public:
    explicit GraphicsRenderEngineImpl(uint64_t id);
    virtual ~GraphicsRenderEngineImpl();
    VEFError Init(OHNativeWindow* outputWindow) override;
    VEFError StartRender() override;
    VEFError StopRender() override;
    VEFError UnInit() override;
    VEFError Render(uint64_t index, const std::shared_ptr<GraphicsRenderInfo>& effectInfo,
        const RenderResultCallback& cb) override;
    OHNativeWindow* GetInputWindow() override;

private:
    void Destroy();
    std::string GetThreadId() const;
    VEFError InitThread();
    void ReleaseThread();
    uint64_t RequestTaskId();
    VEFError InitExportEngine(OHNativeWindow* window);
    VEFError InitSurfaceTexture();
    RenderTexturePtr RenderFrame(const std::shared_ptr<GraphicsRenderInfo>& graphicsRenderInfo);
    RenderTexturePtr RenderEffects(const RenderTexturePtr& inputTexture,
        const std::shared_ptr<GraphicsRenderInfo>& graphicsRenderInfo);
    void DrawFrame(uint64_t pts, const RenderTexturePtr& renderTexture);

private:
    std::recursive_mutex renderMutex_;
    volatile bool ready_ = { false };
    RenderThread<>* renderThread_{ nullptr };
    OHNativeWindow* exportWindow_{ nullptr };
    RenderAttribute attribute_;
    std::shared_ptr<SurfaceTexture> surfaceTexture_{ nullptr };
    RenderSurface* surface_{ nullptr };
    std::shared_ptr<RenderContext> context_{ nullptr };
    std::atomic_uint64_t currentTaskId_{ 0 };

    std::shared_ptr<ShaderPassSurface> shaderPassSurface_ = nullptr;
    std::shared_ptr<ShaderPassOnScreen> shaderPassOnScreen_ = nullptr;
    std::shared_ptr<ShaderPassRotate> shaderPassRotate_ = nullptr;
    std::unordered_map<uint64_t, std::shared_ptr<ImageEffectRender>> imageEffectRenderList_;

    uint64_t id_{ 0 };
};
}
}

#endif
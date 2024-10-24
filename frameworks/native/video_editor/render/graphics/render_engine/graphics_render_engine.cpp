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

#include "render/graphics/graphics_render_engine.h"
#include "graphics_render_engine_impl.h"

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "Render"};
}
static std::atomic_uint64_t g_engineId{ 1 };
std::shared_ptr<IGraphicsRenderEngine> IGraphicsRenderEngine::Create(OHNativeWindow* outputWindow)
{
    if (outputWindow == nullptr) {
        MEDIA_LOGE("create graphics render engine failed, output Window is null.");
        return nullptr;
    }
    auto engine = std::make_shared<GraphicsRenderEngineImpl>(g_engineId.fetch_add(1));
    VEFError error = engine->Init(outputWindow);
    if (error != VEFError::ERR_OK) {
        MEDIA_LOGE("init graphics render engine failed, error: %{public}d", error);
        return nullptr;
    }
    MEDIA_LOGI("init graphic render engine success");
    return engine;
}
}
}
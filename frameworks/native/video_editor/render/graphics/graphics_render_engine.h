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

#ifndef OH_RENDER_ENGINE_INTERFACE_H
#define OH_RENDER_ENGINE_INTERFACE_H

#include "render/graphics/graphics_render_info.h"
#include "external_window.h"
#include "native_avcodec_base.h"

namespace OHOS {
namespace Media {

#ifndef GL_TEXTURE_EXTERNAL_OES
#define GL_TEXTURE_EXTERNAL_OES 0x8D65
#endif

enum class GraphicsRenderResult : uint32_t {
    SUCCESS,
    ERROR,
};

using RenderResultCallback = std::function<void(GraphicsRenderResult result)>;

class IGraphicsRenderEngine {
public:
    static std::shared_ptr<IGraphicsRenderEngine> Create(OHNativeWindow* outputWindow);

    // Init the graphics render engine, parameter window is the output surface of the rendering engine in surface mode.
    // You can set it to xcomponent for screen preview, or as the input surface of the encoder to output data to the
    // encoder after rendering, or as the input surface of components such as vpe for more complex operations.
    virtual VEFError Init(OHNativeWindow* outputWindow) = 0;

    // Uninitialize the rendering engine
    // Before destructing the rendering engine, the caller needs to call this API to release some resources.
    virtual VEFError UnInit() = 0;

    // Start the graphics render engine
    virtual VEFError StartRender() = 0;

    // Stop the graphics render engine
    virtual VEFError StopRender() = 0;

    // Obtain the input surface of the rendering engine.
    // You can set the obtained surface to the decoder. In this way, the data decoded by the decoder is directly sent
    // to the rendering engine through the surface. You can also set the obtained surface to the VPE to process some
    // complex operations, such as color space conversion.
    virtual OHNativeWindow* GetInputWindow() = 0;

    // Render frame data. Index indicates the PTS of the frame. This index is written to the output surface.
    // During encoding, the encoder encodes this index as the PTS of the frame.
    virtual VEFError Render(uint64_t index,
                            const std::shared_ptr<GraphicsRenderInfo>& effectInfo, int32_t rotation,
                            const RenderResultCallback& cb) = 0;
};
} // namespace Media
} // namespace OHOS

#endif // OH_RENDER_ENGINE_INTERFACE_H

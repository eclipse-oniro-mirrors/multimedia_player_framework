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

#ifndef OH_VEF_GRAPHICS_RENDER_CONTEXT_H
#define OH_VEF_GRAPHICS_RENDER_CONTEXT_H

#include "render_object.h"
#include "render_surface.h"

namespace OHOS {
namespace Media {
class RenderContext : public RenderObject {
public:
    RenderContext();
    ~RenderContext() override;

    bool Create(RenderContext* sharedContext);
    bool Init() override;
    bool Release() override;
    bool MakeCurrent(const RenderSurface* surface);
    bool ReleaseCurrent();
    bool SwapBuffers(const RenderSurface* surface);

private:
    EGLDisplay display_;
    EGLContext context_;
};

typedef std::shared_ptr<RenderContext> RenderContextPtr;
}
}

#endif
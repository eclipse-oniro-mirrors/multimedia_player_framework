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

#ifndef OH_VEF_GRAPHICS_RENDER_SURFACE_H
#define OH_VEF_GRAPHICS_RENDER_SURFACE_H

#include "render_attribute.h"
#include "render_object.h"
#include "media_log.h"
#include <EGL/egl.h>
#include "external_window.h"

namespace OHOS {
namespace Media {
class RenderSurface : public RenderObject {
public:
    explicit RenderSurface(std::string tag);
    ~RenderSurface() override;

    void SetAttrib(const RenderAttribute& attrib);
    RenderAttribute GetAttrib();
    bool Create(OHNativeWindow* window);
    bool Init() override;
    bool Release() override;
    void* GetRawSurface() const;

private:
    EGLDisplay display_;
    EGLConfig config_;
    EGLSurface surface_;
    RenderAttribute attribute_;
};
}
}

#endif
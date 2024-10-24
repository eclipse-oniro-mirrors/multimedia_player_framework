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

#ifndef OH_VEF_GRAPHICS_SHADER_PASS_ON_SCREEN_H
#define OH_VEF_GRAPHICS_SHADER_PASS_ON_SCREEN_H

#include "render/graphics/base/render_context.h"
#include "render_general_program.h"
#include "shader_pass.h"

namespace OHOS {
namespace Media {

class ShaderPassOnScreen : public ShaderPass {
public:
    explicit ShaderPassOnScreen(RenderContext* context);
    ~ShaderPassOnScreen() override;

    RenderEffectDataPtr GetRenderEffectData();

    RenderTexturePtr Render() override;

protected:
    void PreDraw() override;
    void PostDraw() override;
};
using ShaderPassOnScreenPtr = std::shared_ptr<ShaderPassOnScreen>;
}
}

#endif
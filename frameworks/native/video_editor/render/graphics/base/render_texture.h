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

#ifndef OH_VEF_GRAPHICS_RENDER_TEXTURE_H
#define OH_VEF_GRAPHICS_RENDER_TEXTURE_H

#include <GLES3/gl3.h>
#include "gl_utils.h"
#include "render_context.h"
#include "render_object.h"

namespace OHOS {
namespace Media {
class RenderTexture : public RenderObject {
public:
    RenderTexture(RenderContext* ctx, GLsizei w, GLsizei h, GLenum interFmt = GL_RGBA8)
    {
        context_ = ctx;
        internalFormat_ = interFmt;
        width_ = w;
        height_ = h;
    }
    ~RenderTexture() override
    {
        Release();
    }

    GLsizei Width()
    {
        return width_;
    }
    GLsizei Height()
    {
        return height_;
    }
    GLenum Format()
    {
        return internalFormat_;
    }

    GLuint GetTextureId()
    {
        return textureId_;
    }

    bool Init() override
    {
        if (!IsReady()) {
            textureId_ = GLUtils::CreateTexture2D(width_, height_, internalFormat_, GL_LINEAR, GL_LINEAR);
            SetReady(true);
        }
        return true;
    }

    bool Release() override
    {
        GLUtils::DeleteTexture(textureId_);
        textureId_ = GL_ZERO;
        width_ = 0;
        height_ = 0;
        SetReady(false);
        return true;
    }

private:
    GLuint textureId_{ GL_ZERO };
    GLsizei width_{ 0 };
    GLsizei height_{ 0 };
    GLenum internalFormat_;
    RenderContext* context_{ nullptr };
};

using RenderTexturePtr = std::shared_ptr<RenderTexture>;

RenderTexturePtr CreateRenderTexture(RenderContext* ctx, GLsizei w, GLsizei h, GLenum interFmt);
}
}

#endif
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

#ifndef OH_VEF_GL_UTILS_H
#define OH_VEF_GL_UTILS_H

#include <GLES3/gl3.h>
#include <cstdint>
#include "math/render_matrix.h"
#include "math/render_vector.h"
#include "render_context.h"

namespace OHOS {
namespace Media {
class GLUtils {
public:
    static GLuint CreateTexture2D(GLsizei width, GLsizei height, GLenum internalFormat, GLint minFilter,
        GLint magFilter);
    
    static GLuint CreateTexture2DNoStorage(GLint minFilter, GLint magFilter, GLint wrapS, GLint wrapT);

    static GLuint CreateFramebuffer(GLuint textureId = 0);

    static void DeleteTexture(GLuint texture);

    static void DeleteFboOnly(GLuint fbo);

    static void CopyTexture(GLuint srcTexId, GLuint dstTexId, GLint width, GLint height);

    static GLuint CreateTexNoStorage(GLenum target);

    static size_t GetInternalFormatPixelByteSize(GLenum internalFormat);

    static GLuint LoadShader(const std::string& src, uint32_t shaderType);

    static GLuint CreateProgram(const std::string& vss, const std::string& fss);

    static Mat4x4 GetOesSamplingMatrix(Vec2 bufferWH, Vec2 displayWH, int32_t angle, bool flip);

    static void CheckError(const char* file, int32_t line);
};
}
}

#endif
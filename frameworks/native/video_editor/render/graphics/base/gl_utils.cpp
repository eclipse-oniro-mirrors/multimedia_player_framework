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

#include <GLES3/gl3.h>
#include <cstdint>
#include "gl_utils.h"
#ifdef USE_M133_SKIA
#include "third_party/skia/third_party/externals/oboe/samples/RhythmGame/third_party/glm/gtc/matrix_transform.hpp"
#else
#include "third_party/externals/oboe/samples/RhythmGame/third_party/glm/gtc/matrix_transform.hpp"
#endif

constexpr uint32_t MESSAGE_MAX_SIZE = 511;

namespace OHOS {
namespace Media {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_VIDEOEDITOR, "VideoEditorRender"};
}
GLuint GLUtils::CreateTexture2D(GLsizei width, GLsizei height, GLenum internalFormat, GLint minFilter,
    GLint magFilter)
{
    GLuint textureId = 0;
    glGenTextures(1, &textureId);
    glBindTexture(GL_TEXTURE_2D, textureId);
    glTexStorage2D(GL_TEXTURE_2D, 1, internalFormat, width, height);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, minFilter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, magFilter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glBindTexture(GL_TEXTURE_2D, GL_NONE);
    return textureId;
}

GLuint GLUtils::CreateTexture2DNoStorage(GLint minFilter, GLint magFilter, GLint wrapS, GLint wrapT)
{
    GLuint tex;
    glGenTextures(1, &tex);
    glBindTexture(GL_TEXTURE_2D, tex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, minFilter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, magFilter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, wrapS);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, wrapT);
    GLUtils::CheckError(__FILE_NAME__, __LINE__);
    return tex;
}

GLuint GLUtils::CreateFramebuffer(GLuint textureId)
{
    GLuint fboId;
    glGenFramebuffers(1, &fboId);
    if (textureId != 0) {
        glBindFramebuffer(GL_FRAMEBUFFER, fboId);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, textureId, 0);
        glBindFramebuffer(GL_FRAMEBUFFER, GL_NONE);
    }
    return fboId;
}

void GLUtils::DeleteTexture(GLuint texture)
{
    if (texture == 0) {
        return;
    }
    glDeleteTextures(1, &texture);
}

void GLUtils::DeleteFboOnly(GLuint fbo)
{
    glDeleteFramebuffers(1, &fbo);
}

void GLUtils::CopyTexture(GLuint srcTexId, GLuint dstTexId, GLint width, GLint height)
{
    glBindTexture(GL_TEXTURE_2D, dstTexId);
    GLuint tempFbo;
    glGenFramebuffers(1, &tempFbo);
    glBindFramebuffer(GL_FRAMEBUFFER, tempFbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, srcTexId, 0);
    glCopyTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 0, 0, width, height);

    glBindTexture(GL_TEXTURE_2D, GL_NONE);
    glBindFramebuffer(GL_FRAMEBUFFER, GL_NONE);
    glDeleteFramebuffers(1, &tempFbo);
}

GLuint GLUtils::CreateTexNoStorage(GLenum target)
{
    GLuint tex;
    glGenTextures(1, &tex);
    glBindTexture(target, tex);
    glTexParameteri(target, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(target, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glTexParameteri(target, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(target, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glBindTexture(target, 0);
    return tex;
}

size_t GLUtils::GetInternalFormatPixelByteSize(GLenum internalFormat)
{
    size_t ret = 0;
    const int32_t ARGS_TWO = 2;
    const int32_t ARGS_EIGHT = 8;
    const int32_t ARGS_FOUR = 4;
    switch (internalFormat) {
        case GL_RGBA8:
        case GL_R32F:
            ret = ARGS_FOUR;
            break;
        case GL_RGBA16F:
            ret = ARGS_EIGHT;
            break;
        case GL_R8:
            ret = 1;
            break;
        case GL_RGB565:
            ret = ARGS_TWO;
            break;
        case GL_RGBA4:
            ret = ARGS_TWO;
            break;
        default:
            break;
    }
    return ret;
}

GLuint GLUtils::LoadShader(const std::string& src, uint32_t shaderType)
{
    const char* tempSrc = src.c_str();
    GLuint shader = glCreateShader(shaderType);
    if (shader == 0) {
        MEDIA_LOGE("Could Not Create Shader!");
        return shader;
    }
    glShaderSource(shader, 1, &tempSrc, nullptr);
    glCompileShader(shader);
    GLint status = GL_FALSE;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &status);
    if (status == GL_FALSE) {
        GLchar message[MESSAGE_MAX_SIZE + 1] = {0};
        glGetShaderInfoLog(shader, MESSAGE_MAX_SIZE, nullptr, &message[0]);
        MEDIA_LOGE("Load Shader Error: %{public}s", message);
        glDeleteShader(shader);
        shader = 0;
    }
    return shader;
}

GLuint GLUtils::CreateProgram(const std::string& vss, const std::string& fss)
{
    GLuint vs = LoadShader(vss, GL_VERTEX_SHADER);
    GLuint fs = LoadShader(fss, GL_FRAGMENT_SHADER);
    if (vs == 0 || fs == 0) {
        return 0;
    }
    GLuint program = glCreateProgram();
    if (program == 0) {
        MEDIA_LOGE("Could Not Create Program!");
        return program;
    }
    glAttachShader(program, vs);
    glAttachShader(program, fs);
    glLinkProgram(program);
    GLint linkStatus = GL_FALSE;
    glGetProgramiv(program, GL_LINK_STATUS, &linkStatus);
    if (linkStatus == GL_FALSE) {
        GLchar message[MESSAGE_MAX_SIZE + 1] = {0};
        glGetShaderInfoLog(program, MESSAGE_MAX_SIZE, nullptr, &message[0]);
        MEDIA_LOGE("Create Program Error: %{public}s", message);
        glDeleteProgram(program);
        program = 0;
        return program;
    }
    if (vs > 0) {
        glDetachShader(program, vs);
        glDeleteShader(vs);
    }
    if (vs > 0) {
        glDetachShader(program, fs);
        glDeleteShader(fs);
    }
    return program;
}

Mat4x4 GLUtils::GetOesSamplingMatrix(Vec2 bufferWH, Vec2 displayWH, int32_t angle, bool flip)
{
    const float half = 0.5;
    Mat4x4 result(1);
    angle = angle / 90 * 90; // 默认旋转角度是90的整数倍
    Vec2 dataWH = (angle == 90 || angle == 270) ? Vec2{ displayWH.y, displayWH.x } : displayWH;
    Vec2 ratioWH = Vec2(dataWH.x / bufferWH.x, dataWH.y / bufferWH.y);
    result = glm::translate(result, Vec3(half, half, 0.0));
    result = glm::rotate(result, glm::radians(-(float)angle), Vec3(0.0, 0.0, 1.0));
    result = glm::translate(result, Vec3(-half, -half, 0.0));
    result[0][0] *= ratioWH.x;
    result[1][1] *= ratioWH.y;
    return result;
}

void GLUtils::CheckError(const char* file, int32_t line)
{
    GLenum status = glGetError();
    if (status != GL_NO_ERROR) {
        MEDIA_LOGE("[Render] GL Error: 0x%{public}x [%{public}s:%{public}d]\n", status, file, line);
    }
}

}
}
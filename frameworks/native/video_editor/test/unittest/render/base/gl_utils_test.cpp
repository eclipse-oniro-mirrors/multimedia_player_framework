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

#include "gtest/gtest.h"
#include "render/graphics/base/gl_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
class GLUtilsTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// test GLUtilsTest CreateTexture2D method
HWTEST_F(GLUtilsTest, GLUtilsTest_CreateTexture2D_001, TestSize.Level0)
{
    GLsizei width = 1024;
    GLsizei height = 1024;
    GLenum internalFormat = GL_RGBA8;
    GLint minFilter = GL_LINEAR;
    GLint magFilter = GL_LINEAR;
    GLuint textureId = GLUtils::CreateTexture2D(width, height, internalFormat, minFilter, magFilter);
    EXPECT_EQ(textureId, 0);
}

// test GLUtilsTest CreateTexture2D method
HWTEST_F(GLUtilsTest, GLUtilsTest_CreateTexture2D_002, TestSize.Level0)
{
    GLsizei width = 0;
    GLsizei height = 0;
    GLenum internalFormat = GL_NONE;
    GLint minFilter = GL_NONE;
    GLint magFilter = GL_NONE;
    GLuint textureId = GLUtils::CreateTexture2D(width, height, internalFormat, minFilter, magFilter);
    EXPECT_EQ(textureId, 0);
}

// test GLUtilsTest CreateTexture2DNoStorage method
HWTEST_F(GLUtilsTest, GLUtilsTest_CreateTexture2DNoStorage, TestSize.Level0)
{
    GLint minFilter = GL_LINEAR;
    GLint magFilter = GL_LINEAR;
    GLint wrapS = GL_CLAMP_TO_EDGE;
    GLint wrapT = GL_CLAMP_TO_EDGE;
    GLuint texture = GLUtils::CreateTexture2DNoStorage(minFilter, magFilter, wrapS, wrapT);
    EXPECT_EQ(texture, 0);
}

// test GLUtilsTest CreateTexture2DNoStorage compare
HWTEST_F(GLUtilsTest, GLUtilsTest_CreateTexture2DNoStorage_compare, TestSize.Level0)
{
    GLint minFilter = GL_LINEAR;
    GLint magFilter = GL_LINEAR;
    GLint wrapS = GL_CLAMP_TO_EDGE;
    GLint wrapT = GL_CLAMP_TO_EDGE;

    GLint minFilter1 = GL_NEAREST;
    GLint magFilter1 = GL_NEAREST;
    GLint wrapS1 = GL_REPEAT;
    GLint wrapT1 = GL_REPEAT;

    GLuint texture1 = GLUtils::CreateTexture2DNoStorage(minFilter, magFilter, wrapS, wrapT);
    GLuint texture2 = GLUtils::CreateTexture2DNoStorage(minFilter1, magFilter1, wrapS1, wrapT1);

    EXPECT_EQ(texture1, texture2);
}

// test GLUtilsTest CreateFramebuffer method
HWTEST_F(GLUtilsTest, GLUtilsTest_CreateFramebuffer_001, TestSize.Level0)
{
    GLuint textureId = 1;
    GLuint fboId = GLUtils::CreateFramebuffer(textureId);
    EXPECT_EQ(fboId, 0);
}

// test GLUtilsTest CreateFramebuffer method
HWTEST_F(GLUtilsTest, GLUtilsTest_CreateFramebuffer_002, TestSize.Level0)
{
    GLuint textureId = 0;
    GLuint fboId = GLUtils::CreateFramebuffer(textureId);
    EXPECT_EQ(fboId, 0);
}

// test GLUtilsTest CreateTexNoStorage method
HWTEST_F(GLUtilsTest, GLUtilsTest_CreateTexNoStorage, TestSize.Level0)
{
    GLenum target = GL_TEXTURE_2D;
    GLuint result = GLUtils::CreateTexNoStorage(target);
    EXPECT_EQ(result, 0);
}

// test GLUtilsTest GetInternalFormatPixelByteSize method
HWTEST_F(GLUtilsTest, GLUtilsTest_GetInternalFormatPixelByteSize_GL_RGBA8, TestSize.Level0)
{
    GLuint result = GLUtils::GetInternalFormatPixelByteSize(GL_RGBA8);
    EXPECT_EQ(result, 4);
}

// test GLUtilsTest GetInternalFormatPixelByteSize method
HWTEST_F(GLUtilsTest, GLUtilsTest_GetInternalFormatPixelByteSize_GL_R32F, TestSize.Level0)
{
    GLuint result = GLUtils::GetInternalFormatPixelByteSize(GL_R32F);
    EXPECT_EQ(result, 4);
}

// test GLUtilsTest GetInternalFormatPixelByteSize method
HWTEST_F(GLUtilsTest, GLUtilsTest_GetInternalFormatPixelByteSize_GL_RGBA16F, TestSize.Level0)
{
    GLuint result = GLUtils::GetInternalFormatPixelByteSize(GL_RGBA16F);
    EXPECT_EQ(result, 8);
}

// test GLUtilsTest GetInternalFormatPixelByteSize method
HWTEST_F(GLUtilsTest, GLUtilsTest_GetInternalFormatPixelByteSize_GL_R8, TestSize.Level0)
{
    GLuint result = GLUtils::GetInternalFormatPixelByteSize(GL_R8);
    EXPECT_EQ(result, 1);
}

// test GLUtilsTest GetInternalFormatPixelByteSize method
HWTEST_F(GLUtilsTest, GLUtilsTest_GetInternalFormatPixelByteSize_GL_RGB565, TestSize.Level0)
{
    GLuint result = GLUtils::GetInternalFormatPixelByteSize(GL_RGB565);
    EXPECT_EQ(result, 2);
}

// test GLUtilsTest GetInternalFormatPixelByteSize method
HWTEST_F(GLUtilsTest, GLUtilsTest_GetInternalFormatPixelByteSize_GL_RGBA4, TestSize.Level0)
{
    GLuint result = GLUtils::GetInternalFormatPixelByteSize(GL_RGBA4);
    EXPECT_EQ(result, 2);
}

// test GLUtilsTest GetInternalFormatPixelByteSize method
HWTEST_F(GLUtilsTest, GLUtilsTest_GetInternalFormatPixelByteSize_GL_NONE, TestSize.Level0)
{
    GLuint result = GLUtils::GetInternalFormatPixelByteSize(GL_NONE);
    EXPECT_EQ(result, 0);
}

// test GLUtilsTest LoadShader method
HWTEST_F(GLUtilsTest, GLUtilsTest_LoadShader, TestSize.Level0)
{
    std::string validShaderSrc = "#version 330 core\nvoid main(){ gl_FragColor = vec4(1.0, 1.0, 1.0, 1.0);}";
    uint32_t shaderType = GL_FRAGMENT_SHADER;
    GLuint shader = GLUtils::LoadShader(validShaderSrc, shaderType);
    EXPECT_EQ(shader, 0);
}

// test GLUtilsTest CreateProgram method
HWTEST_F(GLUtilsTest, GLUtilsTest_CreateProgram, TestSize.Level0)
{
    std::string vss = "valid vertex shader source";
    std::string fss = "valid fragment shader source";
    GLuint program = GLUtils::CreateProgram(vss, fss);
    EXPECT_EQ(program, 0);
}

// test GLUtilsTest GetOesSamplingMatrix method
HWTEST_F(GLUtilsTest, GLUtilsTest_GetOesSamplingMatrix, TestSize.Level0)
{
    Vec2 bufferWH = {100, 100};
    Vec2 displayWH = {100, 100};
    int32_t angle = 0;
    bool flip = true;
    Mat4x4 expected = Mat4x4(1);
    expected[0][0] = 1;
    expected[1][1] = 1;
    EXPECT_EQ(GLUtils::GetOesSamplingMatrix(bufferWH, displayWH, angle, flip), expected);
}
} // namespace Media
} // namespace OHOS
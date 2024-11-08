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
#include "render/graphics/effect/image_effect_render.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
class ImageEffectRenderTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// test ImageEffectRenderTest Init method
HWTEST_F(ImageEffectRenderTest, ImageEffectRenderTest_Init, TestSize.Level0)
{
    std::shared_ptr<OH_ImageEffect> imageEffect;
    ImageEffectRender imageEffectRender(imageEffect);
    ASSERT_FALSE(imageEffectRender.Init());
}

// test ImageEffectRenderTest Release method
HWTEST_F(ImageEffectRenderTest, ImageEffectRenderTest_Release, TestSize.Level0)
{
    std::shared_ptr<OH_ImageEffect> imageEffect;
    ImageEffectRender imageEffectRender(imageEffect);
    ASSERT_TRUE(imageEffectRender.Release());
}

// test ImageEffectRenderTest InitNativeBuffer method
HWTEST_F(ImageEffectRenderTest, ImageEffectRenderTest_InitNativeBuffer, TestSize.Level0)
{
    std::shared_ptr<OH_ImageEffect> imageEffect;
    ImageEffectRender imageEffectRender(imageEffect);
    ASSERT_EQ(imageEffectRender.InitEffectFilter(), VEFError::ERR_INTERNAL_ERROR);
}

// test ImageEffectRenderTest Render method
HWTEST_F(ImageEffectRenderTest, ImageEffectRenderTest_Render, TestSize.Level0)
{
    std::shared_ptr<OH_ImageEffect> imageEffect;
    ImageEffectRender imageEffectRender(imageEffect);
    RenderTexturePtr inputRenderTexture;
    ASSERT_EQ(imageEffectRender.Render(nullptr, nullptr, inputRenderTexture, 1), inputRenderTexture);
}
} // namespace Media
} // namespace OHOS
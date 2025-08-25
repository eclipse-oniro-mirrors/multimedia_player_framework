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
#include "render/graphics/base/surface_texture.h"
#include "render/graphics/base/render_context.h"
#include "ut_common_data.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class SurfaceTextureTest : public testing::Test {
protected:
    void SetUp() override
    {
        context_ = new RenderContext();
    }

    void TearDown() override
    {
        if (context_ != nullptr) {
            delete context_;
            context_ = nullptr;
        }
    }

private:
    RenderContext* context_ = nullptr;
};

HWTEST_F(SurfaceTextureTest, OnFrameAvailable_context_nullptr, TestSize.Level0)
{
    SurfaceTexture surfaceText;
    surfaceText.OnFrameAvailable(nullptr);
    EXPECT_EQ(surfaceText.frameNum_, 0);
}

HWTEST_F(SurfaceTextureTest, AwaitNativeImage_frameNum_default, TestSize.Level0)
{
    SurfaceTexture surfaceText;
    surfaceText.AwaitNativeImage();
    EXPECT_EQ(surfaceText.frameNum_, 0);
}

HWTEST_F(SurfaceTextureTest, AwaitNativeImage_frameNum_three, TestSize.Level0)
{
    SurfaceTexture surfaceText;
    surfaceText.frameNum_ = 3;
    surfaceText.AwaitNativeImage();
    EXPECT_EQ(surfaceText.frameNum_, 2);
}

HWTEST_F(SurfaceTextureTest, AwaitNativeImage_frameNum_negative_one, TestSize.Level0)
{
    SurfaceTexture surfaceText;
    surfaceText.frameNum_ = -1;
    surfaceText.AwaitNativeImage();
    EXPECT_EQ(surfaceText.frameNum_, -2);
}
} // namespace Media
} // namespace OHOS
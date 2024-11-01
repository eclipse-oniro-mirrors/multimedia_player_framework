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
#include "render/graphics/base/render_surface.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
class RenderSurfaceTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// test RenderSurfaceTest Create method
HWTEST_F(RenderSurfaceTest, RenderSurfaceTest_Create, TestSize.Level0)
{
    std::string tagStr = "render_module";
    RenderSurface renderSurface(tagStr);
    EXPECT_FALSE(renderSurface.Create(nullptr));
}

// test RenderSurfaceTest Init method
HWTEST_F(RenderSurfaceTest, RenderSurfaceTest_Init, TestSize.Level0)
{
    std::string tagStr = "render_module";
    RenderSurface renderSurface(tagStr);
    EXPECT_FALSE(renderSurface.Init());
}

// test RenderSurfaceTest Release method return true
HWTEST_F(RenderSurfaceTest, RenderSurfaceTest_Release_true, TestSize.Level0)
{
    std::string tagStr = "render_module";
    RenderSurface renderSurface(tagStr);
    renderSurface.SetReady(false);
    EXPECT_TRUE(renderSurface.Release());
}

// test RenderSurfaceTest Release method return false
HWTEST_F(RenderSurfaceTest, RenderSurfaceTest_Render_false, TestSize.Level0)
{
    std::string tagStr = "render_module";
    RenderSurface renderSurface(tagStr);
    renderSurface.SetReady(true);
    EXPECT_FALSE(renderSurface.Release());
}
} // namespace Media
} // namespace OHOS
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
#include "render/graphics/base/render_context.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
class RenderContextTest : public testing::Test {
protected:
    void SetUp() override
    {
        renderContext = new RenderContext();
    }

    void TearDown() override
    {
        if (renderContext != nullptr) {
            delete renderContext;
            renderContext = nullptr;
        }
    }

private:
    RenderContext* renderContext;
};

// test RenderContextTest Create method
HWTEST_F(RenderContextTest, RenderContextTest_Create, TestSize.Level0)
{
    // verify function can return normally(whatever the GL context is valid or not)
    bool result = renderContext->Create(nullptr);
    EXPECT_TRUE(result);
}

// test RenderContextTest Init method
HWTEST_F(RenderContextTest, RenderContextTest_Init, TestSize.Level0)
{
    bool result = renderContext->Init();
    EXPECT_TRUE(result);
}

// test RenderContextTest Release method
HWTEST_F(RenderContextTest, RenderContextTest_Release, TestSize.Level0)
{
    renderContext->SetReady(true);
    // Release should return false when context is ready
    EXPECT_TRUE(renderContext->IsReady());
    // verify function can return normally(whatever the GL context is valid or not)
    bool result = renderContext->Release();
    EXPECT_FALSE(result);
}

HWTEST_F(RenderContextTest, RenderContextTest_Release_true, TestSize.Level0)
{
    renderContext->SetReady(false);
    EXPECT_FALSE(renderContext->IsReady());
    // verify function can return normally(whatever the GL context is valid or not)
    bool result = renderContext->Release();
    EXPECT_TRUE(result);
}

// test RenderContextTest MakeCurrent method
HWTEST_F(RenderContextTest, RenderContextTest_MakeCurrent, TestSize.Level0)
{
    renderContext->SetReady(true);
    EXPECT_TRUE(renderContext->IsReady());
    // verify ready state should not influence MakeCurrent function
    bool result = renderContext->MakeCurrent(nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(RenderContextTest, RenderContextTest_MakeCurrent_false, TestSize.Level0)
{
    renderContext->SetReady(false);
    EXPECT_FALSE(renderContext->IsReady());
    // verify ready state should not influence MakeCurrent function
    bool result = renderContext->MakeCurrent(nullptr);
    EXPECT_FALSE(result);
}

// test RenderContextTest ReleaseCurrent method
HWTEST_F(RenderContextTest, RenderContextTest_ReleaseCurrent, TestSize.Level0)
{
    renderContext->SetReady(true);
    EXPECT_TRUE(renderContext->IsReady());
    // if not init render context successfully, ReleaseCurrent should return false
    bool result = renderContext->ReleaseCurrent();
    EXPECT_FALSE(result);
}

HWTEST_F(RenderContextTest, RenderContextTest_ReleaseCurrent_false, TestSize.Level0)
{
    renderContext->SetReady(false);
    // if not init render context successfully, ReleaseCurrent should return false
    EXPECT_FALSE(renderContext->IsReady());
    bool result = renderContext->ReleaseCurrent();
    EXPECT_FALSE(result);
}

// test RenderContextTest SwapBuffers method
HWTEST_F(RenderContextTest, RenderContextTest_SwapBuffers, TestSize.Level0)
{
    renderContext->SetReady(true);
    EXPECT_TRUE(renderContext->IsReady());
    bool result = renderContext->SwapBuffers(nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(RenderContextTest, RenderContextTest_SwapBuffers_surface_not_nullptr, TestSize.Level0)
{
    renderContext->SetReady(true);
    EXPECT_TRUE(renderContext->IsReady());
    auto surface = new (std::nothrow) RenderSurface(std::string());
    ASSERT_NE(surface, nullptr);
    bool result = renderContext->SwapBuffers(surface);
    EXPECT_FALSE(result);
    delete surface;
    surface = nullptr;
}
} // namespace Media
} // namespace OHOS
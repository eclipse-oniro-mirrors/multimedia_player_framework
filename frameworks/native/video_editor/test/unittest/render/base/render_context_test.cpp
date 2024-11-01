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
    EXPECT_FALSE(renderContext->Create(nullptr));
}

// test RenderContextTest Init method
HWTEST_F(RenderContextTest, RenderContextTest_Init, TestSize.Level0)
{
    EXPECT_FALSE(renderContext->Init());
}

// test RenderContextTest Release method
HWTEST_F(RenderContextTest, RenderContextTest_Release, TestSize.Level0)
{
    renderContext->SetReady(true);
    EXPECT_FALSE(renderContext->Release());
}

// test RenderContextTest MakeCurrent method
HWTEST_F(RenderContextTest, RenderContextTest_MakeCurrent, TestSize.Level0)
{
    renderContext->SetReady(true);
    EXPECT_FALSE(renderContext->MakeCurrent(nullptr));
}

// test RenderContextTest ReleaseCurrent method
HWTEST_F(RenderContextTest, RenderContextTest_ReleaseCurrent, TestSize.Level0)
{
    renderContext->SetReady(true);
    EXPECT_FALSE(renderContext->ReleaseCurrent());
}

// test RenderContextTest SwapBuffers method
HWTEST_F(RenderContextTest, RenderContextTest_SwapBuffers, TestSize.Level0)
{
    renderContext->SetReady(true);
    EXPECT_FALSE(renderContext->SwapBuffers(nullptr));
}
} // namespace Media
} // namespace OHOS
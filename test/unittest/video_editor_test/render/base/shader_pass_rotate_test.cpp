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
#include "render/graphics/base/shader_pass/shader_pass_rotate.h"
#include "render/graphics/base/shader_pass/shader_pass_program.h"
#include "render/graphics/base/shader_pass/shader_pass.h"
#include "ut_common_data.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class ShaderPassRotateTest : public testing::Test {
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

HWTEST_F(ShaderPassRotateTest, ShaderPassRotateTest_PreDraw_shade_nullptr, TestSize.Level0)
{
    auto shaderPassRotate = std::make_shared<ShaderPassRotate>(context_);
    ASSERT_NE(shaderPassRotate, nullptr);
    shaderPassRotate->PreDraw();
    ASSERT_NE(shaderPassRotate->Render(), nullptr);
}

HWTEST_F(ShaderPassRotateTest, ShaderPassRotateTest_PreDraw_shade_not_nullptr, TestSize.Level0)
{
    auto shaderPassRotate = std::make_shared<ShaderPassRotate>(context_);
    ASSERT_NE(shaderPassRotate, nullptr);
    shaderPassRotate->shader_ = std::make_shared<ShaderPassProgram>(context_, SURFACE_VERTEX_SHADER_CODE,
        SURFACE_ROTATE_FRAGMENT_SHADER_CODE);
    ASSERT_NE(shaderPassRotate->shader_, nullptr);
    shaderPassRotate->PreDraw();
}

HWTEST_F(ShaderPassRotateTest, ShaderPassRotateTest_PostDraw_shade_nullptr, TestSize.Level0)
{
    auto shaderPassRotate = std::make_shared<ShaderPassRotate>(context_);
    ASSERT_NE(shaderPassRotate, nullptr);
    shaderPassRotate->PostDraw();
}
} // namespace Media
} // namespace OHOS
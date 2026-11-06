/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "native_avscreen_capture_impl.h"
#include <gtest/gtest.h>
#include <native_buffer.h>
#include <surface_type.h>

using namespace testing::ext;

namespace OHOS {
namespace Media {
class NativeBufferRefTest : public testing::Test {
public:
    static constexpr int32_t BUFFER_SIZE = 64;
    void SetUp() override
    {
        OH_NativeBuffer_Config cfg;
        cfg.width = BUFFER_SIZE;
        cfg.height = BUFFER_SIZE;
        cfg.format = GRAPHIC_PIXEL_FMT_RGBA_8888;
        cfg.usage = static_cast<int32_t>(NATIVEBUFFER_USAGE_CPU_READ);
        cfg.stride = 0;
        buffer_ = OH_NativeBuffer_Alloc(&cfg);
        buffer2_ = OH_NativeBuffer_Alloc(&cfg);
    }

    void TearDown() override
    {
        if (buffer_ != nullptr) {
            OH_NativeBuffer_Unreference(buffer_);
            buffer_ = nullptr;
        }
        if (buffer2_ != nullptr) {
            OH_NativeBuffer_Unreference(buffer2_);
            buffer2_ = nullptr;
        }
    }

protected:
    OH_NativeBuffer *buffer_ = nullptr;
    OH_NativeBuffer *buffer2_ = nullptr;
    NativeBufferRef ref_;
    NativeBufferRef ref2_;
};

HWTEST_F(NativeBufferRefTest, Acquire_Success_001, TestSize.Level2)
{
    ref_ = NativeBufferRef::Acquire(buffer_);
    ASSERT_TRUE(ref_);
    ASSERT_EQ(ref_.get(), buffer_);
}

HWTEST_F(NativeBufferRefTest, Acquire_Failure_001, TestSize.Level2)
{
    ref_ = NativeBufferRef::Acquire(nullptr);
    ASSERT_FALSE(ref_);
    ASSERT_EQ(ref_.get(), nullptr);
}

HWTEST_F(NativeBufferRefTest, DefaultEmpty_001, TestSize.Level2)
{
    ASSERT_FALSE(ref_);
    ASSERT_EQ(ref_.get(), nullptr);
}

HWTEST_F(NativeBufferRefTest, MoveCtor_001, TestSize.Level2)
{
    ref_ = NativeBufferRef::Acquire(buffer_);
    ref2_ = NativeBufferRef(std::move(ref_));
    ASSERT_FALSE(ref_);
    ASSERT_TRUE(ref2_);
    ASSERT_EQ(ref2_.get(), buffer_);
}

HWTEST_F(NativeBufferRefTest, MoveAssign_NonSelf_001, TestSize.Level2)
{
    ref_ = NativeBufferRef::Acquire(buffer_);
    ref2_ = NativeBufferRef::Acquire(buffer2_);
    ref_ = std::move(ref2_);
    ASSERT_EQ(ref_.get(), buffer2_);
    ASSERT_FALSE(ref2_);
}

HWTEST_F(NativeBufferRefTest, MoveAssign_ToEmpty_001, TestSize.Level2)
{
    ref_ = NativeBufferRef::Acquire(buffer_);
    ref2_ = std::move(ref_);
    ASSERT_EQ(ref2_.get(), buffer_);
    ASSERT_FALSE(ref_);
}

HWTEST_F(NativeBufferRefTest, MoveAssign_Self_001, TestSize.Level2)
{
    ref_ = NativeBufferRef::Acquire(buffer_);
    OH_NativeBuffer *before = ref_.get();
    ref_ = std::move(ref_);
    ASSERT_EQ(ref_.get(), before);
    ASSERT_TRUE(ref_);
}

HWTEST_F(NativeBufferRefTest, Release_001, TestSize.Level2)
{
    ref_ = NativeBufferRef::Acquire(buffer_);
    OH_NativeBuffer *p = ref_.release();
    ASSERT_EQ(p, buffer_);
    ASSERT_FALSE(ref_);
    OH_NativeBuffer_Unreference(p);
    ASSERT_EQ(ref_.get(), nullptr);
}
} // namespace Media
} // namespace OHOS

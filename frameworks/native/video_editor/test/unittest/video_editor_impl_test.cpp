/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "video_editor_impl.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoEditorImplTest : public ::testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// Test VideoEditorImpl constructor with valid id
HWTEST_F(VideoEditorImplTest, video_editor_impl_construct, TestSize.Level0)
{
    uint64_t id = 12345;
    VideoEditorImpl videoEditor(id);
    ASSERT_EQ(videoEditor.GetId(), id);
}

// Test VideoEditorImpl Init method
HWTEST_F(VideoEditorImplTest, video_editor_impl_init_ok, TestSize.Level0)
{
    uint64_t id = 12345;
    VideoEditorImpl videoEditor(id);
    ASSERT_EQ(videoEditor.Init(), VEFError::ERR_OK);
}

// Test VideoEditorImpl AppendVideoFile method
HWTEST_F(VideoEditorImplTest, video_editor_impl_append_video_file_ok, TestSize.Level0)
{
    uint64_t id = 12345;
    VideoEditorImpl videoEditor(id);
    ASSERT_EQ(videoEditor.AppendVideoFile(1, "test_effect"), VEFError::ERR_OK);
}

// Test VideoEditorImpl StartComposite method
HWTEST_F(VideoEditorImplTest, video_editor_impl_start_composite_ok, TestSize.Level0)
{
    uint64_t id = 12345;
    VideoEditorImpl videoEditor(id);
    ASSERT_EQ(videoEditor.StartComposite(nullptr), VEFError::ERR_OK);
}

// Test VideoEditorImpl CancelComposite method
HWTEST_F(VideoEditorImplTest, video_editor_impl_cancel_composite_ok, TestSize.Level0)
{
    uint64_t id = 12345;
    VideoEditorImpl videoEditor(id);
    ASSERT_EQ(videoEditor.CancelComposite(), VEFError::ERR_OK);
}

} // namespace Media
} // namespace OHOS

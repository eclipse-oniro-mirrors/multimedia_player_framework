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
#include "ut_common_data.h"
#include "video_editor_impl.h"
#include "video_editor_manager.h"
#include <fcntl.h>

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
        VideoEditorManager::GetInstance().id_ = 1;
        VideoEditorManager::GetInstance().editorMap_.clear();
    }
};

// Test VideoEditorImpl constructor with valid id
HWTEST_F(VideoEditorImplTest, construct, TestSize.Level0)
{
    uint64_t id = 12345;
    VideoEditorImpl videoEditor(id);
    ASSERT_EQ(videoEditor.GetId(), id);
}

// Test VideoEditorImpl Init method
HWTEST_F(VideoEditorImplTest, init_ok, TestSize.Level0)
{
    uint64_t id = 12345;
    VideoEditorImpl videoEditor(id);
    ASSERT_EQ(videoEditor.Init(), VEFError::ERR_OK);
}

// Test VideoEditorImpl AppendVideoFile method
HWTEST_F(VideoEditorImplTest, append_video_file_invalid_effect_description, TestSize.Level0)
{
    auto videoEditor = VideoEditorManager::GetInstance().CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
    ASSERT_NE(videoEditor->AppendVideoFile(1, "test_effect"), VEFError::ERR_OK);
}

// Test VideoEditorImpl AppendVideoFile method
HWTEST_F(VideoEditorImplTest, append_video_file_invalid_fd_1, TestSize.Level0)
{
    auto videoEditor = VideoEditorManager::GetInstance().CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
    ASSERT_NE(videoEditor->AppendVideoFile(-1, "test_effect"), VEFError::ERR_OK);
}

// Test VideoEditorImpl AppendVideoFile method
HWTEST_F(VideoEditorImplTest, append_video_file_invalid_fd_0, TestSize.Level0)
{
    auto videoEditor = VideoEditorManager::GetInstance().CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
    ASSERT_NE(videoEditor->AppendVideoFile(0, "test_effect"), VEFError::ERR_OK);
}

// Test VideoEditorImpl StartComposite method
HWTEST_F(VideoEditorImplTest, start_composite_error, TestSize.Level0)
{
    auto videoEditor = VideoEditorManager::GetInstance().CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
    auto cb = std::make_shared<CompositionCallbackTesterImpl>();
    auto options = std::make_shared<CompositionOptions>(5, cb);
    ASSERT_EQ(videoEditor->StartComposite(options), VEFError::ERR_NOT_SET_INPUT_VIDEO);
}

// Test VideoEditorImpl StartComposite method
HWTEST_F(VideoEditorImplTest, start_composite_repead, TestSize.Level0)
{
    auto videoEditor = VideoEditorManager::GetInstance().CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
    auto cb = std::make_shared<CompositionCallbackTesterImpl>();
    auto options = std::make_shared<CompositionOptions>(5, cb);
    ASSERT_EQ(videoEditor->StartComposite(options), VEFError::ERR_NOT_SET_INPUT_VIDEO);
    ASSERT_EQ(videoEditor->CancelComposite(), VEFError::ERR_OK);
}

// Test VideoEditorImpl StartComposite method
HWTEST_F(VideoEditorImplTest, start_composite_nullptr_options, TestSize.Level0)
{
    auto videoEditor = VideoEditorManager::GetInstance().CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
    ASSERT_NE(videoEditor->StartComposite(nullptr), VEFError::ERR_OK);
}

// Test VideoEditorImpl StartComposite method
HWTEST_F(VideoEditorImplTest, start_composite_nullptr_cb, TestSize.Level0)
{
    auto videoEditor = VideoEditorManager::GetInstance().CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
    auto cb = std::make_shared<CompositionCallbackTesterImpl>();
    auto options = std::make_shared<CompositionOptions>(8, nullptr);
    ASSERT_NE(videoEditor->StartComposite(nullptr), VEFError::ERR_OK);
}

// Test VideoEditorImpl StartComposite with invalid target file fd method.
HWTEST_F(VideoEditorImplTest, start_composite_invalid_target_fd, TestSize.Level0)
{
    auto videoEditor = VideoEditorManager::GetInstance().CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
    auto cb = std::make_shared<CompositionCallbackTesterImpl>();
    auto options = std::make_shared<CompositionOptions>(-1, cb);
    ASSERT_NE(videoEditor->StartComposite(options), VEFError::ERR_OK);
}

// Test when VideoEditorImpl::IsFlowControlPass() returns true.
HWTEST_F(VideoEditorImplTest, cancel_composite_ok, TestSize.Level0)
{
    auto cb = std::make_shared<CompositionCallbackTesterImpl>();
    auto options = std::make_shared<CompositionOptions>(5, cb);

    auto videoEditor = VideoEditorFactory::CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
    ASSERT_EQ(videoEditor->StartComposite(options), VEFError::ERR_NOT_SET_INPUT_VIDEO);
    ASSERT_EQ(videoEditor->CancelComposite(), VEFError::ERR_OK);
}

HWTEST_F(VideoEditorImplTest, CreateCompositeEngine_return_nullptr, TestSize.Level0)
{
    auto compositeEngine = ICompositeEngine::CreateCompositeEngine(nullptr);
    ASSERT_EQ(compositeEngine, nullptr);
}
} // namespace Media
} // namespace OHOS

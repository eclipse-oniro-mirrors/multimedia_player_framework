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
#include "video_editor.h"
#include "video_editor_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoEditorManagerTest : public testing::Test {
public:
    void SetUp() override
    {
    }

    void TearDown() override
    {
        VideoEditorManager::GetInstance().id_ = 1;
        VideoEditorManager::GetInstance().editorMap_.clear();
    }
};

// Test CreateVideoEditor when VideoEditorImpl Init returns success.
HWTEST_F(VideoEditorManagerTest, create_video_editor_init_success, TestSize.Level0)
{
    EXPECT_NE(VideoEditorManager::GetInstance().CreateVideoEditor(), nullptr);
}

// Test ReleaseVideoEditor when editorMap contains the id.
HWTEST_F(VideoEditorManagerTest, release_video_editor_exist, TestSize.Level0)
{
    auto editor = VideoEditorManager::GetInstance().CreateVideoEditor();
    EXPECT_EQ(VideoEditorManager::GetInstance().editorMap_.count(1), 1);
    VideoEditorManager::GetInstance().ReleaseVideoEditor(1);
    EXPECT_EQ(VideoEditorManager::GetInstance().editorMap_.count(1), 0);
}

// Test auto ReleaseVideoEditor when editorMap not contains the id.
HWTEST_F(VideoEditorManagerTest, auto_release_video_editor_exist, TestSize.Level0)
{
    auto editor = VideoEditorManager::GetInstance().CreateVideoEditor();
    EXPECT_EQ(VideoEditorManager::GetInstance().editorMap_.count(1), 1);
    editor = nullptr;
    EXPECT_EQ(VideoEditorManager::GetInstance().editorMap_.count(1), 0);
}

// Test ReleaseVideoEditor when editorMap does not contain the id.
HWTEST_F(VideoEditorManagerTest, release_video_editor_not_exist, TestSize.Level0)
{
    VideoEditorManager::GetInstance().ReleaseVideoEditor(1);
    EXPECT_EQ(VideoEditorManager::GetInstance().editorMap_.count(1), 0);
}

// Test when VideoEditorImpl::Init() returns ERR_OK.
HWTEST_F(VideoEditorManagerTest, factory_create_video_editor_ok, TestSize.Level0)
{
    auto videoEditor = VideoEditorFactory::CreateVideoEditor();
    ASSERT_NE(videoEditor, nullptr);
}

} // namespace Media
} // namespace OHOS

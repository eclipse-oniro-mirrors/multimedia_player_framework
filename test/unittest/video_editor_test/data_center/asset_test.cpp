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
#include "data_center/asset/asset.h"
#include "data_center/asset/asset_factory.h"
#include "data_center/asset/video_asset.h"
#include "data_center/effect/effect.h"
#include "data_center/effect/effect_factory.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class VideoAssetTest : public ::testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// Test AssetFactory::CreateAsset ok
HWTEST_F(VideoAssetTest, asset_factory_create_asset_ok, TestSize.Level0)
{
    auto asset = AssetFactory::CreateAsset(AssetType::VIDEO, 5);
    ASSERT_NE(asset, nullptr);
}

// Test AssetFactory::CreateAsset fail
HWTEST_F(VideoAssetTest, asset_factory_create_asset_unsupported_type_unknown, TestSize.Level0)
{
    auto asset = AssetFactory::CreateAsset(AssetType::UNKNOWN, 5);
    ASSERT_EQ(asset, nullptr);
}

// Test AssetFactory::CreateAsset fail
HWTEST_F(VideoAssetTest, asset_factory_create_asset_unsupported_type_audio, TestSize.Level0)
{
    auto asset = AssetFactory::CreateAsset(AssetType::AUDIO, 5);
    ASSERT_EQ(asset, nullptr);
}

// Test AssetFactory::CreateAsset fail
HWTEST_F(VideoAssetTest, asset_factory_create_asset_invalid_file_fd, TestSize.Level0)
{
    auto asset = AssetFactory::CreateAsset(AssetType::VIDEO, -1);
    ASSERT_EQ(asset, nullptr);
}

// Test video asset contructor
HWTEST_F(VideoAssetTest, video_asset_contructor, TestSize.Level0)
{
    VideoAsset videoAsset(5, 100);
    ASSERT_EQ(videoAsset.GetId(), 5);
    ASSERT_EQ(videoAsset.GetFd(), 100);
    ASSERT_EQ(videoAsset.GetType(), AssetType::VIDEO);
}

// Test video asset apply effect
HWTEST_F(VideoAssetTest, video_asset_apply_effect_fail, TestSize.Level0)
{
    VideoAsset videoAsset(5, 100);
    videoAsset.ApplyEffect(nullptr);
    ASSERT_EQ(videoAsset.GetEffectList().empty(), true);
}

// Test video asset contructor
HWTEST_F(VideoAssetTest, video_asset_get_effect_list, TestSize.Level0)
{
    VideoAsset videoAsset(5, 100);
    ASSERT_EQ(videoAsset.GetEffectList().empty(), true);
}

} // namespace Media
} // namespace OHOS

/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "downloaded_cache_loader_test.h"
#include "downloaded_cache_loader.cpp"
#include "cache_manager.cpp"

using namespace testing;
using namespace testing::Ext;

namespace OHOS {
namespace Media {

HWTEST_F(DownloadedCacheLoaderTest, Constructor_001, TestSize.Level0)
{
    auto manager = std::make_shared<DownloadedCacheManager>("/data/cache");
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->GetCacheDir(), "/data/cache");
}

HWTEST_F(DownloadedCacheLoaderTest, GetCacheDir_001, TestSize.Level0)
{
    auto manager = std::make_shared<DownloadedCacheManager>("/test/cache");
    ASSERT_NE(manager, nullptr);
    EXPECT_EQ(manager->GetCacheDir(), "/test/cache");
}

HWTEST_F(DownloadedCacheLoaderTest, GetMediaCache_NewUrl_001, TestSize.Level0)
{
    auto manager = std::make_shared<DownloadedCacheManager>("/data/cache");
    ASSERT_NE(manager, nullptr);
    std::string result = manager->GetMediaCache("http://example.com/test.mp4");
    EXPECT_EQ(result, "");
}

HWTEST_F(DownloadedCacheLoaderTest, GetMediaCache_EmptyUrl_001, TestSize.Level0)
{
    auto manager = std::make_shared<DownloadedCacheManager>("/data/cache");
    ASSERT_NE(manager, nullptr);
    std::string result = manager->GetMediaCache("");
    EXPECT_EQ(result, "");
}

HWTEST_F(DownloadedCacheLoaderTest, GetCacheMetaData_NotFound_001, TestSize.Level0)
{
    auto manager = std::make_shared<DownloadedCacheManager>("/data/cache");
    ASSERT_NE(manager, nullptr);
    CacheMetaData metadata;
    bool result = manager->GetCacheMetaData("http://nonexistent.com/test.mp4", metadata);
    EXPECT_FALSE(result);
}

HWTEST_F(DownloadedCacheLoaderTest, BuildHttpHeaders_NotFound_001, TestSize.Level0)
{
    auto manager = std::make_shared<DownloadedCacheManager>("/data/cache");
    ASSERT_NE(manager, nullptr);
    auto headers = manager->BuildHttpHeaders("http://nonexistent.com/test.mp4");
    EXPECT_TRUE(headers.empty());
}

HWTEST_F(DownloadedCacheLoaderTest, GetRootUrl_001, TestSize.Level0)
{
    auto manager = std::make_shared<DownloadedCacheManager>("/data/cache");
    ASSERT_NE(manager, nullptr);
    std::string rootUrl = manager->GetRootUrl();
    EXPECT_EQ(rootUrl, "");
}

HWTEST_F(DownloadedCacheLoaderTest, CacheMetaData_Struct_001, TestSize.Level0)
{
    CacheMetaData metadata;
    metadata.type = "video/mp4";
    metadata.randomAccess = true;
    metadata.size = 1024;
    metadata.url = "http://example.com/test.mp4";
    metadata.entry = "test.mp4";

    EXPECT_EQ(metadata.type, "video/mp4");
    EXPECT_TRUE(metadata.randomAccess);
    EXPECT_EQ(metadata.size, 1024);
    EXPECT_EQ(metadata.url, "http://example.com/test.mp4");
    EXPECT_EQ(metadata.entry, "test.mp4");
}

HWTEST_F(DownloadedCacheLoaderTest, MultipleInstances_001, TestSize.Level0)
{
    auto manager1 = std::make_shared<DownloadedCacheManager>("/cache1");
    auto manager2 = std::make_shared<DownloadedCacheManager>("/cache2");
    ASSERT_NE(manager1, nullptr);
    ASSERT_NE(manager2, nullptr);
    EXPECT_EQ(manager1->GetCacheDir(), "/cache1");
    EXPECT_EQ(manager2->GetCacheDir(), "/cache2");
}

} // namespace Media
} // namespace OHOS

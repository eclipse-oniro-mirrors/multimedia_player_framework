/*
* Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include <sys/mman.h>
#include <fcntl.h>
#include "cache_manager_test.h"
#include "media_errors.h"
using namespace std;
using namespace testing;
using namespace testing::ext;
namespace fs = std::filesystem;

namespace OHOS {
namespace Media {
static const std::string CACHE_DIR = "/data/storage/el2/base/cache/avplayer_media_loader";
static const std::string CACHE_MAPPING_FILE = "cache_mapping.txt";
static const uint64_t MAX_CACHE_FILE_SIZE = 4ULL * 1024ULL * 1024ULL * 1024ULL;
static const uint64_t CACHE_FILE_SIZE_WATERLINE = 3ULL * 1024ULL * 1024ULL * 1024ULL;

void CacheManagerTest::SetUpTestCase(void)
{
}

void CacheManagerTest::TearDownTestCase(void)
{
}

void CacheManagerTest::SetUp(void)
{
    manager_ = std::make_unique<StreamCacheManager>();
}

void CacheManagerTest::TearDown(void)
{
}

/**
* @tc.name  : CacheManagerTest_StaticCreate_001
* @tc.number: StaticCreate_001
* @tc.desc  : test create singleton
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_StaticCreate_001, TestSize.Level0)
{
    // 第一次调用Create方法
    auto instance1 = StreamCacheManager::Create();
    ASSERT_NE(instance1, nullptr);

    // 第二次调用Create方法
    auto instance2 = StreamCacheManager::Create();
    ASSERT_EQ(instance1, instance2);
}

/**
* @tc.name  : CacheManagerTest_CreateMediaCache_001
* @tc.number: CreateMediaCache_001
* @tc.desc  : test CreateMediaCache
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_CreateMediaCache_001, TestSize.Level0)
{
    std::string url = "http://example.com/video.mp4";
    std::string type = "video";
    bool randomAccess = true;
    uint64_t size = 1024;

    bool result = manager_->CreateMediaCache(url, type, randomAccess, size);

    EXPECT_TRUE(result);
    std::string entry = manager_->GetMediaCache(url);
    manager_->fd_ = -1;

    EXPECT_NE(entry, "");
}

/**
* @tc.name  : CacheManagerTest_CreateMediaCache_002
* @tc.number: CreateMediaCache_002
* @tc.desc  : test CreateMediaCache
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_CreateMediaCache_002, TestSize.Level0)
{
    std::string url = "http://example.com/video.mp4";
    std::string type = "video";
    bool randomAccess = true;
    uint64_t size = 1024;

    manager_->CreateMediaCache(url, type, randomAccess, size);

    bool result = manager_->CreateMediaCache(url, type, randomAccess, size);

    EXPECT_TRUE(result);
}

/**
* @tc.name  : CacheManagerTest_CreateMediaCache_003
* @tc.number: CreateMediaCache_003
* @tc.desc  : test CreateMediaCache
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_CreateMediaCache_003, TestSize.Level0)
{
    std::string url = "http://example.com/video.mp4";
    std::string type = "video";
    bool randomAccess = true;
    uint64_t size = 1024;

    bool result = manager_->CreateMediaCache(url, type, randomAccess, size);

    EXPECT_TRUE(result);
}

/**
* @tc.name  : CacheManagerTest_FindFirstEqualField_001
* @tc.number: FindFirstEqualField_001
* @tc.desc  : test FindFirstEqualField false
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_FindFirstEqualField_001, TestSize.Level0)
{
    std::string url = "http://example.com/video.mp4";
    std::string type = "video";
    bool randomAccess = true;
    uint64_t size = 1024;

    manager_->CreateMediaCache(url, type, randomAccess, size);
    std::string key = std::to_string(std::hash<std::string>()(url));
    auto it = manager_->index_.find(key);
    CacheEntryInfo info;
    bool result = manager_->FindFirstEqualField(it->second, info, "a", CacheFieldId::REQUEST_URL);
    EXPECT_FALSE(result);
}

/**
* @tc.name  : CacheManagerTest_FlushWriteLength_001
* @tc.number: FlushWriteLength_001
* @tc.desc  : test cacheSize > MAX_CACHE_FILE_SIZE
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_FlushWriteLength_001, TestSize.Level0)
{
    std::string url = "http://example.com/audio.mp3";
    std::string type = "audio";
    bool randomAccess = true;
    uint64_t size = 1024;

    manager_->CreateMediaCache(url, type, randomAccess, size);
    std::string path = "test_path";
    uint64_t fileSize = MAX_CACHE_FILE_SIZE + 1;

    bool result = manager_->FlushWriteLength(path, fileSize);
    EXPECT_TRUE(result);
}

/**
* @tc.name  : CacheManagerTest_FlushWriteLength_002
* @tc.number: FlushWriteLength_002
* @tc.desc  : test cacheSize < MAX_CACHE_FILE_SIZE
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_FlushWriteLength_002, TestSize.Level0)
{
    std::string path = "test_path";
    uint64_t fileSize = 1024;

    manager_->entryIndex_["test_entry"] = "test_timestamp";
    manager_->cacheSize_.store(fileSize);

    bool result = manager_->FlushWriteLength(path, fileSize);
    EXPECT_TRUE(result);
}

/**
* @tc.name  : CacheManagerTest_FlushWriteLength_003
* @tc.number: FlushWriteLength_003
* @tc.desc  : test cacheSize true
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_FlushWriteLength_003, TestSize.Level0)
{
    std::string path = "test_path";
    uint64_t fileSize = 1024;

    manager_->entryIndex_["test_entry"] = "test_timestamp";
    manager_->cacheSize_.store(fileSize);

    manager_->index_["test_key"].emplace_back(CacheEntryInfo());
    manager_->mapped_ = new char[1024];

    bool result = manager_->FlushWriteLength(path, fileSize);
    EXPECT_TRUE(result);
}

/**
* @tc.name  : CacheManagerTest_GetPrefixBeforeUnderscore_001
* @tc.number: GetPrefixBeforeUnderscore_001
* @tc.desc  : test not included _
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_GetPrefixBeforeUnderscore_001, TestSize.Level0)
{
    std::string input = "testDir";
    std::string output = manager_->GetPrefixBeforeUnderscore(input);
    EXPECT_EQ(output, input);
}

/**
* @tc.name  : CacheManagerTest_GetPrefixBeforeUnderscore_002
* @tc.number: GetPrefixBeforeUnderscore_002
* @tc.desc  : test included _
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_GetPrefixBeforeUnderscore_002, TestSize.Level0)
{
    std::string input = "test_Dir";
    std::string output = manager_->GetPrefixBeforeUnderscore(input);
    EXPECT_EQ(output, "test");
}

/**
* @tc.name  : CacheManagerTest_FlushCacheSize_001
* @tc.number: FlushCacheSize_001
* @tc.desc  : test cacheSize_ < flushSize
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_FlushCacheSize_001, TestSize.Level0)
{
    manager_->cacheSize_.store(100, std::memory_order_relaxed);
    uint64_t size = 200;

    manager_->FlushCacheSize(size);

    EXPECT_EQ(manager_->cacheSize_.load(), 0);
}

/**
* @tc.name  : CacheManagerTest_FlushCacheSize_002
* @tc.number: FlushCacheSize_002
* @tc.desc  : test cacheSize_ > flushSize
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_FlushCacheSize_002, TestSize.Level0)
{
    manager_->cacheSize_.store(300, std::memory_order_relaxed);
    uint64_t size = 200;

    manager_->FlushCacheSize(size);

    EXPECT_EQ(manager_->cacheSize_.load(), 100);
}

/**
* @tc.name  : CacheManagerTest_RemoveCacheDirectory_001
* @tc.number: RemoveCacheDirectory_001
* @tc.desc  : test dir size > 800MB
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_RemoveCacheDirectory_001, TestSize.Level0)
{
    std::string url = "http://example.com/audio.mp3";
    std::string type = "audio";
    bool randomAccess = true;
    uint64_t size = 1024;
    manager_->cacheSize_.store(CACHE_FILE_SIZE_WATERLINE, std::memory_order_relaxed);
    manager_->CreateMediaCache(url, type, randomAccess, size);
    std::string dir = manager_->GetMediaCache(url);
    std::string path = dir + "/temp";
    fs::create_directories(path);
    for (int i = 0; i < 3; i++) {
        std::string filename = dir + "/" + std::to_string(i);
        std::ofstream file(filename, std::ios::binary | std::ios::trunc);
        file.seekp(400ULL * 1024ULL * 1024ULL, std::ios::beg);
        file.put('\0');
        file.close();
        manager_->FlushWriteLength(filename, 400ULL * 1024ULL * 1024ULL);
    }
    bool result = manager_->cacheSize_.load() < MAX_CACHE_FILE_SIZE;
    EXPECT_TRUE(result);
}

/**
* @tc.name  : CacheManagerTest_ExtractField_001
* @tc.number: RemoveCacheDirectory_001
* @tc.desc  : test ExtractField
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_ExtractField_001, TestSize.Level0)
{
    std::string url = "http://example.com/audio.mp3";
    std::string type = "audio";
    bool randomAccess = true;
    uint64_t size = 1024;
    manager_->CreateMediaCache(url, type, randomAccess, size);
    EXPECT_TRUE(manager_->mapped_ != MAP_FAILED);
    char* ptr = static_cast<char*>(manager_->mapped_);
    std::string result = manager_->ExtractField(ptr, 0, CacheFieldId::REQUEST_URL);
    EXPECT_EQ(result, "");
}

/**
* @tc.name  : CacheManagerTest_LoadIndex_001
* @tc.number: LoadIndex_001
* @tc.desc  : test LoadIndex
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_LoadIndex_001, TestSize.Level0)
{
    std::string url = "http://example.com/audio.mp3";
    std::string type = "audio";
    bool randomAccess = true;
    uint64_t size = 1024;
    manager_->CreateMediaCache(url, type, randomAccess, size);
    EXPECT_TRUE(manager_->mapped_ != MAP_FAILED);
    char* ptr = static_cast<char*>(manager_->mapped_);
    CacheEntryHeader* header = reinterpret_cast<CacheEntryHeader*>(ptr);
    header->fieldCount = 100;
    manager_->LoadIndex();
    EXPECT_TRUE(manager_->index_.empty());
}

/**
* @tc.name  : CacheManagerTest_UpdateLastAccessTime_001
* @tc.number: UpdateLastAccessTime_001
* @tc.desc  : test UpdateLastAccessTime
*/
HWTEST_F(CacheManagerTest, CacheManagerTest_UpdateLastAccessTime_001, TestSize.Level0)
{
    std::string url = "http://example.com/audio.mp3";
    std::string type = "audio";
    bool randomAccess = true;
    uint64_t size = 1024;
    manager_->CreateMediaCache(url, type, randomAccess, size);
    EXPECT_TRUE(manager_->mapped_ != MAP_FAILED);
    std::string key = std::to_string(std::hash<std::string>()(url));
    auto it = manager_->index_.find(key);
    EXPECT_TRUE(it != manager_->index_.end());

    CacheEntryInfo info;
    manager_->FindFirstEqualField(it->second, info, url, CacheFieldId::REQUEST_URL);
    char* ptr = static_cast<char*>(manager_->mapped_) + info.offset;
    CacheEntryHeader* header = reinterpret_cast<CacheEntryHeader*>(ptr);
    CacheField* filedHeaders = reinterpret_cast<CacheField*>(ptr + sizeof(CacheEntryHeader));
    for (size_t i = 0; i < header->fieldCount; i++) {
        filedHeaders[i].id = 0;
    }
    EXPECT_FALSE(manager_->UpdateLastAccessTime(info, key));
}
}
}
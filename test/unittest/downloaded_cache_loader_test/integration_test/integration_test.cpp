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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <map>
#include <thread>
#include <securec.h>
#include "../common/downloaded_cache_test_common.h"
#include "downloaded_cache_loader.h"
#include "cache_manager.h"
#include "cache_reader.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace DownloadedCache {

class MockLoadingRequest : public LoadingRequest {
public:
    explicit MockLoadingRequest(const std::string& url) : url_(url),
        respondHeaderCalled_(false), respondDataCalled_(false),
        finishLoadingCalled_(false), finishLoadingCode_(0) {}

    std::string GetUrl() override { return url_; }

    std::map<std::string, std::string> GetHeader() override { return responseHeaders_; }

    uint64_t GetUniqueId() override { return 0; }

    int32_t RespondHeader(int64_t uuid, std::map<std::string, std::string> header, std::string redirectUrl) override
    {
        respondHeaderCalled_ = true;
        responseHeaders_ = header;
        return 0;
    }

    int32_t RespondData(int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory>& mem) override
    {
        respondDataCalled_ = true;
        responseOffset_ = offset;
        responseBuffer_ = mem;
        return 0;
    }

    int32_t FinishLoading(int64_t uuid, int32_t code) override
    {
        finishLoadingCalled_ = true;
        finishLoadingCode_ = code;
        return 0;
    }

    bool IsRespondHeaderCalled() const { return respondHeaderCalled_; }
    bool IsRespondDataCalled() const { return respondDataCalled_; }
    bool IsFinishLoadingCalled() const { return finishLoadingCalled_; }
    int32_t GetFinishLoadingCode() const { return finishLoadingCode_; }
    const std::map<std::string, std::string>& GetResponseHeaders() const { return responseHeaders_; }

private:
    std::string url_;
    std::atomic<bool> respondHeaderCalled_;
    std::atomic<bool> respondDataCalled_;
    std::atomic<bool> finishLoadingCalled_;
    std::atomic<int32_t> finishLoadingCode_;
    std::map<std::string, std::string> responseHeaders_;
    int64_t responseOffset_;
    std::shared_ptr<AVSharedMemory> responseBuffer_;
};

class IntegrationTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void)
    {
        testCacheDir_ = TestCommon::GetTestCacheDir("integration");
        TestCommon::SetupTestDirectory(testCacheDir_);

        testUrl_ = "http://example.com/test.mp4";
        testPath_ = "videos/test.mp4";
        testData_ = std::vector<uint8_t>(1024, 'A'); // 1024 is 1KB
        for (size_t i = 0; i < testData_.size(); i++) {
            testData_[i] = static_cast<uint8_t>(i % 256); // 256 mod for uint8_t
        }

        TestCommon::CreateTestCacheFile(testCacheDir_, testPath_, testData_);
        TestCommon::CreateTestMappingFile(testCacheDir_, {{testUrl_, testPath_}});

        cacheManager_ = std::make_shared<DownloadedCacheManager>(testCacheDir_);
        cacheLoader_ = std::make_shared<DownloadedCacheLoader>(cacheManager_);
    }
    void TearDown(void)
    {
        cacheLoader_.reset();
        cacheManager_.reset();
        TestCommon::CleanupTestDirectory(testCacheDir_);
    }
protected:
    std::string testCacheDir_;
    std::string testUrl_;
    std::string testPath_;
    std::vector<uint8_t> testData_;
    std::shared_ptr<DownloadedCacheManager> cacheManager_;
    std::shared_ptr<DownloadedCacheLoader> cacheLoader_;
};

HWTEST_F(IntegrationTest, Open_CacheNotFound_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>("http://example.com/nonexistent.mp4");
    auto requestPtr = std::shared_ptr<LoadingRequest>(request);

    int64_t uuid = cacheLoader_->Open(requestPtr);
    EXPECT_LT(uuid, 0);
    EXPECT_TRUE(request->IsFinishLoadingCalled());
    EXPECT_NE(request->GetFinishLoadingCode(), 0);
}

HWTEST_F(IntegrationTest, Open_NullRequest_001, TestSize.Level0)
{
    std::shared_ptr<LoadingRequest> nullRequest = nullptr;
    int64_t uuid = cacheLoader_->Open(nullRequest);
    EXPECT_LT(uuid, 0);
}

HWTEST_F(IntegrationTest, Read_InvalidUuid_001, TestSize.Level0)
{
    cacheLoader_->Read(-1, 0, 100);
    cacheLoader_->Read(999999, 0, 100);
}

HWTEST_F(IntegrationTest, EmptyCacheDir_001, TestSize.Level0)
{
    auto manager = std::make_shared<DownloadedCacheManager>("");
    auto loader = std::make_shared<DownloadedCacheLoader>(manager);

    auto request = std::make_shared<MockLoadingRequest>(testUrl_);
    std::shared_ptr<LoadingRequest> requestPtr = request;
    int64_t uuid = loader->Open(requestPtr);
    EXPECT_LT(uuid, 0);
}

HWTEST_F(IntegrationTest, Open_EmptyUrl_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>("");
    std::shared_ptr<LoadingRequest> requestPtr = request;
    int64_t uuid = cacheLoader_->Open(requestPtr);
    EXPECT_LT(uuid, 0);
}

HWTEST_F(IntegrationTest, CacheReader_CloseBeforeRead_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>(testUrl_);
    std::shared_ptr<LoadingRequest> requestPtr = request;

    auto readTask = std::make_shared<Task>("OS_Custom_Read_Test", "", TaskType::SINGLETON, TaskPriority::HIGH, false);
    auto cacheReader = std::make_shared<CacheReader>(1, requestPtr, readTask, cacheManager_);

    int64_t openResult = cacheReader->Open(requestPtr);
    EXPECT_GE(openResult, 0);

    cacheReader->Close(openResult);
    cacheReader->Read(openResult, 0, 100);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_FALSE(request->IsRespondHeaderCalled());
    EXPECT_FALSE(request->IsRespondDataCalled());
}

HWTEST_F(IntegrationTest, E2E_FilterRoundTrip, TestSize.Level0)
{
    std::string cacheDir = TestCommon::GetTestCacheDir("e2e_filter");
    TestCommon::SetupTestDirectory(cacheDir);

    std::string url = "http://example.com/test.mp4";
    std::string path = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(cacheDir, path, std::vector<uint8_t>(1024, 'A'));

    Plugins::TrackSelectionFilter filter;
    filter.maxVideoBitrate = 5000000;
    filter.minVideoBitrate = 100000;
    filter.maxVideoFrameRate = 60;
    filter.minVideoFrameRate = 24;
    filter.maxVideoResolution = {1920, 1080};
    filter.minVideoResolution = {640, 480};
    filter.preferredVideoMimeTypes = {"video/avc", "video/hevc"};
    filter.maxAudioBitrate = 320000;
    filter.minAudioBitrate = 48000;
    filter.maxAudioChannels = 2;
    filter.preferredAudioMimeTypes = {"audio/mp4a-latm"};
    filter.preferredAudioLanguages = {"eng", "chi"};
    filter.preferredSubtitleLanguages = {"chi"};
    TestCommon::CreateTestMappingFileWithFilter(cacheDir, {{url, path}}, filter);

    auto manager = std::make_shared<DownloadedCacheManager>(cacheDir);
    EXPECT_TRUE(manager->HasTrackSelectionFilter());
    auto loaded = manager->GetTrackSelectionFilter();
    EXPECT_EQ(loaded.maxVideoBitrate, 5000000);
    EXPECT_EQ(loaded.minVideoBitrate, 100000);
    EXPECT_EQ(loaded.maxVideoFrameRate, 60);
    EXPECT_EQ(loaded.minVideoFrameRate, 24);
    EXPECT_EQ(loaded.maxVideoResolution.first, 1920);
    EXPECT_EQ(loaded.maxVideoResolution.second, 1080);
    EXPECT_EQ(loaded.minVideoResolution.first, 640);
    EXPECT_EQ(loaded.minVideoResolution.second, 480);
    EXPECT_EQ(loaded.preferredVideoMimeTypes.size(), 2);
    EXPECT_EQ(loaded.preferredVideoMimeTypes[0], "video/avc");
    EXPECT_EQ(loaded.preferredAudioLanguages.size(), 2);
    EXPECT_EQ(loaded.preferredAudioLanguages[0], "eng");
    EXPECT_EQ(loaded.preferredSubtitleLanguages.size(), 1);
    std::string mediaCache = manager->GetMediaCache(url);
    EXPECT_FALSE(mediaCache.empty());

    TestCommon::CleanupTestDirectory(cacheDir);
}

HWTEST_F(IntegrationTest, E2E_KeyCrossCdnMatch, TestSize.Level0)
{
    std::string cacheDir = TestCommon::GetTestCacheDir("e2e_key");
    TestCommon::SetupTestDirectory(cacheDir);

    std::string downloadUrl = "https://cdn1.example.com/path/video.m3u8";
    std::string path = "videos/video.m3u8";
    TestCommon::CreateTestCacheFile(cacheDir, path, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFileWithKey(cacheDir, {{downloadUrl, path}});

    auto manager = std::make_shared<DownloadedCacheManager>(cacheDir);
    auto loader = std::make_shared<DownloadedCacheLoader>(manager);

    std::string mediaCache = manager->GetMediaCache(downloadUrl);
    EXPECT_FALSE(mediaCache.empty());

    auto request = std::make_shared<MockLoadingRequest>(downloadUrl);
    std::shared_ptr<LoadingRequest> requestPtr = request;
    int64_t uuid = loader->Open(requestPtr);
    EXPECT_GE(uuid, 0);

    TestCommon::CleanupTestDirectory(cacheDir);
}

HWTEST_F(IntegrationTest, E2E_NoKeyFallback, TestSize.Level0)
{
    std::string cacheDir = TestCommon::GetTestCacheDir("e2e_nokey");
    TestCommon::SetupTestDirectory(cacheDir);

    std::string url = "http://example.com/test.mp4";
    std::string path = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(cacheDir, path, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(cacheDir, {{url, path}});

    auto manager = std::make_shared<DownloadedCacheManager>(cacheDir, "");
    EXPECT_FALSE(manager->HasTrackSelectionFilter());

    std::string mediaCache = manager->GetMediaCache(url);
    EXPECT_FALSE(mediaCache.empty());

    TestCommon::CleanupTestDirectory(cacheDir);
}

HWTEST_F(IntegrationTest, E2E_FilterAndKeyCombined, TestSize.Level1)
{
    std::string cacheDir = TestCommon::GetTestCacheDir("e2e_combo");
    TestCommon::SetupTestDirectory(cacheDir);

    std::string downloadUrl = "https://cdn1.example.com/path/video.m3u8";
    std::string path = "videos/video.m3u8";
    TestCommon::CreateTestCacheFile(cacheDir, path, std::vector<uint8_t>(1024, 'A'));

    Plugins::TrackSelectionFilter filter;
    filter.maxVideoBitrate = 8000000;
    filter.preferredVideoMimeTypes = {"video/avc"};
    filter.preferredAudioLanguages = {"eng"};
    TestCommon::CreateTestMappingFileWithFilter(cacheDir, {{downloadUrl, path}},
        filter, downloadUrl);

    auto manager = std::make_shared<DownloadedCacheManager>(cacheDir);
    EXPECT_TRUE(manager->HasTrackSelectionFilter());
    auto loaded = manager->GetTrackSelectionFilter();
    EXPECT_EQ(loaded.maxVideoBitrate, 8000000);
    EXPECT_EQ(loaded.preferredVideoMimeTypes.size(), 1);
    EXPECT_EQ(loaded.preferredAudioLanguages.size(), 1);

    std::string mediaCache = manager->GetMediaCache(downloadUrl);
    EXPECT_FALSE(mediaCache.empty());

    TestCommon::CleanupTestDirectory(cacheDir);
}

HWTEST_F(IntegrationTest, E2E_OldCacheCompatibility, TestSize.Level0)
{
    std::string cacheDir = TestCommon::GetTestCacheDir("e2e_old");
    TestCommon::SetupTestDirectory(cacheDir);

    std::string url = "http://example.com/test.mp4";
    std::string path = "videos/test.mp4";
    TestCommon::CreateTestCacheFile(cacheDir, path, std::vector<uint8_t>(1024, 'A'));
    TestCommon::CreateTestMappingFile(cacheDir, {{url, path}});

    auto manager = std::make_shared<DownloadedCacheManager>(cacheDir, "");
    EXPECT_FALSE(manager->HasTrackSelectionFilter());

    CacheMetaData metadata;
    bool result = manager->GetCacheMetaData(url, metadata);
    EXPECT_TRUE(result);
    EXPECT_EQ(metadata.entry, path);

    std::string mediaCache = manager->GetMediaCache(url);
    EXPECT_FALSE(mediaCache.empty());

    TestCommon::CleanupTestDirectory(cacheDir);
}

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS
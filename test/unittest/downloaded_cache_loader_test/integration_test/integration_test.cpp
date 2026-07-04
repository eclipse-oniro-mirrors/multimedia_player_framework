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

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS
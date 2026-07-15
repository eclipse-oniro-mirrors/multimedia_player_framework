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

#include <algorithm>
#include <gtest/gtest.h>
#include <string>
#include <memory>
#include <vector>
#include <map>
#include <fstream>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "net_downloader_test_common.h"
#include "downloader.h"
#include "download_network_client.h"
#include "http_server_demo.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace MediaDownload {

class TestableNetworkClient : public NetworkClient {
public:
    using NetworkClient::ProcessHttp416RangeNotSatisfiable;
    using NetworkClient::Handle416WithoutContentRange;
    using NetworkClient::ParseContentRangeTotalSize;
    using NetworkClient::CompareAndSetDownloadResult;
    using NetworkClient::IsValidUrl;
    using NetworkClient::HandleRangeResume;
    using NetworkClient::WriteData;
    using NetworkClient::RxHeaderCallback;

    TestableNetworkClient(const std::string &url, const std::map<std::string, std::string> &header,
        int32_t timeoutMs, int32_t retryCount)
        : NetworkClient(url, header, timeoutMs, retryCount) {}

    std::shared_ptr<DownloadContext> GetContext()
    {
        return ctx_;
    }

    void SetStartPos(int64_t startPos)
    {
        startPos_ = startPos;
    }

    int64_t GetStartPos() const
    {
        return startPos_;
    }

    void SetResponseHeader(const std::string &key, const std::string &value)
    {
        std::lock_guard<std::mutex> lock(ctx_->mutex);
        std::string normalizedKey = key;
        std::transform(normalizedKey.begin(), normalizedKey.end(), normalizedKey.begin(), ::tolower);
        ctx_->responseHeaders[normalizedKey] = value;
    }

    void SetHttpStatusCode(int32_t code)
    {
        ctx_->httpStatusCode.store(code);
    }

    void SetDownloadedSize(int64_t size)
    {
        ctx_->downloadedSize.store(size);
    }

    void SetOutputFd(int fd)
    {
        ctx_->outputFd = fd;
    }

    void SetProgressCallback(ProgressCallback cb)
    {
        progressCallback_ = cb;
    }

    void SetErrorCallback(ErrorCallback cb)
    {
        errorCallback_ = cb;
    }

    int64_t GetStartPosValue() const
    {
        return startPos_;
    }
};

class NetworkClientExtTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void)
    {
        testDir_ = TestCommon::GetTestCacheDir("network_client_ext_test");
        TestCommon::SetupTestDirectory(testDir_);
    }
    void TearDown(void)
    {
        TestCommon::CleanupTestDirectory(testDir_);
    }
protected:
    std::string testDir_;
};

HWTEST_F(NetworkClientExtTest, HandleRangeResume_StartPosZero_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    (void)client->SetOutputPath(testDir_ + "/handle_range_resume_test.mp4");
    client->SetStartPos(0);
    client->SetDownloadedSize(0);
    
    bool result = client->HandleRangeResume(client->GetContext().get(), client.get());
    EXPECT_TRUE(result);
}

HWTEST_F(NetworkClientExtTest, HandleRangeResume_DownloadedSizeNonZero_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    (void)client->SetOutputPath(testDir_ + "/handle_range_resume_test2.mp4");
    client->SetStartPos(100);
    client->SetDownloadedSize(50);
    
    bool result = client->HandleRangeResume(client->GetContext().get(), client.get());
    EXPECT_TRUE(result);
}

HWTEST_F(NetworkClientExtTest, HandleRangeResume_WithContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    (void)client->SetOutputPath(testDir_ + "/handle_range_resume_test3.mp4");
    client->SetStartPos(100);
    client->SetDownloadedSize(0);
    client->SetResponseHeader("Content-Range", "bytes 100-199/200");
    
    bool result = client->HandleRangeResume(client->GetContext().get(), client.get());
    EXPECT_TRUE(result);
    EXPECT_EQ(client->GetStartPosValue(), 100);
}

HWTEST_F(NetworkClientExtTest, WriteData_InvalidFd_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    (void)client->SetOutputPath(testDir_ + "/write_data_test.mp4");
    client->SetOutputFd(-1);
    
    char buffer[100] = "test data";
    size_t result = client->WriteData(client->GetContext().get(), client.get(), buffer, 100);
    EXPECT_EQ(result, 100);
}

HWTEST_F(NetworkClientExtTest, WriteData_Success_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    std::string filePath = testDir_ + "/write_data_success_test.mp4";
    (void)client->SetOutputPath(filePath);
    
    char buffer[100] = "test data for write";
    size_t result = client->WriteData(client->GetContext().get(), client.get(), buffer, 100);
    EXPECT_EQ(result, 100);
    
    struct stat st;
    EXPECT_EQ(stat(filePath.c_str(), &st), 0);
    EXPECT_GT(st.st_size, 0);
}

HWTEST_F(NetworkClientExtTest, WriteData_WithProgressCallback_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    std::string filePath = testDir_ + "/write_data_progress_test.mp4";
    (void)client->SetOutputPath(filePath);
    
    bool callbackInvoked = false;
    client->SetProgressCallback([&callbackInvoked](int64_t downloadedSize, int64_t totalSize) {
        callbackInvoked = true;
    });
    
    char buffer[100] = "test data";
    size_t result = client->WriteData(client->GetContext().get(), client.get(), buffer, 100);
    EXPECT_EQ(result, 100);
    EXPECT_TRUE(callbackInvoked);
}

HWTEST_F(NetworkClientExtTest, ParseContentRangeTotalSize_ValidFormat_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    int64_t serverTotalSize = 0;
    bool result = client->ParseContentRangeTotalSize("bytes 100-199/1024", serverTotalSize);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(serverTotalSize, 1024);
}

HWTEST_F(NetworkClientExtTest, ParseContentRangeTotalSize_ValidFormat_002, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    int64_t serverTotalSize = 0;
    bool result = client->ParseContentRangeTotalSize("bytes 0-99/2048", serverTotalSize);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(serverTotalSize, 2048);
}

HWTEST_F(NetworkClientExtTest, ParseContentRangeTotalSize_LargeFile_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    int64_t serverTotalSize = 0;
    bool result = client->ParseContentRangeTotalSize("bytes 500000-999999/104857600", serverTotalSize);
    
    EXPECT_TRUE(result);
    EXPECT_EQ(serverTotalSize, 104857600);
}

HWTEST_F(NetworkClientExtTest, ParseContentRangeTotalSize_NoSlash_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    int64_t serverTotalSize = 0;
    bool result = client->ParseContentRangeTotalSize("bytes 100-199/abc", serverTotalSize);
    
    EXPECT_FALSE(result);
}

HWTEST_F(NetworkClientExtTest, ParseContentRangeTotalSize_InvalidFormat_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    int64_t serverTotalSize = 0;
    bool result = client->ParseContentRangeTotalSize("bytes */*", serverTotalSize);
    
    EXPECT_FALSE(result);
}

HWTEST_F(NetworkClientExtTest, ParseContentRangeTotalSize_EmptyTotalSize_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    int64_t serverTotalSize = 0;
    bool result = client->ParseContentRangeTotalSize("bytes 100-199/", serverTotalSize);
    
    EXPECT_FALSE(result);
}

HWTEST_F(NetworkClientExtTest, ParseContentRangeTotalSize_ZeroTotalSize_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    int64_t serverTotalSize = 0;
    bool result = client->ParseContentRangeTotalSize("bytes 100-199/0", serverTotalSize);
    
    EXPECT_FALSE(result);
}

HWTEST_F(NetworkClientExtTest, CompareAndSetDownloadResult_EqualSizes_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(1024);
    (void)client->SetOutputPath(testDir_ + "/compare_test.mp4");
    
    client->CompareAndSetDownloadResult(1024);
    
    auto ctx = client->GetContext();
    EXPECT_TRUE(ctx->requestSuccess.load());
    EXPECT_EQ(ctx->totalSize.load(), 1024);
}

HWTEST_F(NetworkClientExtTest, CompareAndSetDownloadResult_MismatchSizes_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(1024);
    (void)client->SetOutputPath(testDir_ + "/mismatch_test.mp4");
    
    client->CompareAndSetDownloadResult(2048);
    
    auto ctx = client->GetContext();
    EXPECT_FALSE(ctx->requestSuccess.load());
}

HWTEST_F(NetworkClientExtTest, CompareAndSetDownloadResult_ServerLarger_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(1024);
    (void)client->SetOutputPath(testDir_ + "/server_larger_test.mp4");
    
    client->CompareAndSetDownloadResult(2048);
    
    auto ctx = client->GetContext();
    EXPECT_FALSE(ctx->requestSuccess.load());
}

HWTEST_F(NetworkClientExtTest, CompareAndSetDownloadResult_ServerSmaller_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(2048);
    (void)client->SetOutputPath(testDir_ + "/server_smaller_test.mp4");
    
    client->CompareAndSetDownloadResult(1024);
    
    auto ctx = client->GetContext();
    EXPECT_FALSE(ctx->requestSuccess.load());
}

HWTEST_F(NetworkClientExtTest, Handle416WithoutContentRange_StartPosPositive_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(1024);
    (void)client->SetOutputPath(testDir_ + "/handle416_1.mp4");
    
    client->Handle416WithoutContentRange();
    
    auto ctx = client->GetContext();
    EXPECT_TRUE(ctx->requestSuccess.load());
    EXPECT_EQ(ctx->totalSize.load(), 1024);
}

HWTEST_F(NetworkClientExtTest, Handle416WithoutContentRange_StartPosZero_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(0);
    (void)client->SetOutputPath(testDir_ + "/handle416_2.mp4");
    
    client->Handle416WithoutContentRange();
    
    auto ctx = client->GetContext();
    EXPECT_FALSE(ctx->requestSuccess.load());
}

HWTEST_F(NetworkClientExtTest, ProcessHttp416RangeNotSatisfiable_WithContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(2048);
    (void)client->SetOutputPath(testDir_ + "/process416_1.mp4");
    client->SetResponseHeader("Content-Range", "bytes 1024-2047/2048");
    
    client->ProcessHttp416RangeNotSatisfiable();
    
    auto ctx = client->GetContext();
    EXPECT_TRUE(ctx->requestSuccess.load());
    EXPECT_EQ(ctx->totalSize.load(), 2048);
}

HWTEST_F(NetworkClientExtTest, ProcessHttp416RangeNotSatisfiable_WithContentRange_SizeMismatch_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(1024);
    (void)client->SetOutputPath(testDir_ + "/process416_3.mp4");
    client->SetResponseHeader("Content-Range", "bytes 1024-2047/3000");
    
    client->ProcessHttp416RangeNotSatisfiable();
    
    auto ctx = client->GetContext();
    EXPECT_FALSE(ctx->requestSuccess.load());
}

HWTEST_F(NetworkClientExtTest, ProcessHttp416RangeNotSatisfiable_WithoutContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(500);
    (void)client->SetOutputPath(testDir_ + "/process416_4.mp4");
    
    client->ProcessHttp416RangeNotSatisfiable();
    
    auto ctx = client->GetContext();
    EXPECT_TRUE(ctx->requestSuccess.load());
}

HWTEST_F(NetworkClientExtTest, ProcessHttp416RangeNotSatisfiable_WithoutContentRange_ZeroStart_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(0);
    (void)client->SetOutputPath(testDir_ + "/process416_5.mp4");
    
    client->ProcessHttp416RangeNotSatisfiable();
    
    auto ctx = client->GetContext();
    EXPECT_FALSE(ctx->requestSuccess.load());
}

HWTEST_F(NetworkClientExtTest, ProcessHttp416RangeNotSatisfiable_InvalidContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(1024);
    (void)client->SetOutputPath(testDir_ + "/process416_6.mp4");
    client->SetResponseHeader("Content-Range", "bytes */*");
    
    client->ProcessHttp416RangeNotSatisfiable();
    
    auto ctx = client->GetContext();
    EXPECT_FALSE(ctx->requestSuccess.load());
}

HWTEST_F(NetworkClientExtTest, ProcessHttp416RangeNotSatisfiable_EmptyContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    client->SetStartPos(1024);
    (void)client->SetOutputPath(testDir_ + "/process416_7.mp4");
    client->SetResponseHeader("Content-Range", "");
    
    client->ProcessHttp416RangeNotSatisfiable();
    
    auto ctx = client->GetContext();
    EXPECT_FALSE(ctx->requestSuccess.load());
}

HWTEST_F(NetworkClientExtTest, WriteData_ErrorCallback_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
    
    std::string filePath = testDir_ + "/write_error_test.mp4";
    int fd = open(filePath.c_str(), O_WRONLY | O_CREAT, 0644);
    EXPECT_GE(fd, 0);
    close(fd);
    (void)client->SetOutputPath(filePath);
    
    bool errorCallbackInvoked = false;
    client->SetErrorCallback([&errorCallbackInvoked](DownloadErrorType errorType, int32_t errorCode) {
        errorCallbackInvoked = true;
    });
    
    char buffer[100] = "test data";
    size_t result = client->WriteData(client->GetContext().get(), client.get(), buffer, 100);
    EXPECT_EQ(result, 100);
}

HWTEST_F(NetworkClientExtTest, HandleRangeResume_LowerCaseContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    (void)client->SetOutputPath(testDir_ + "/range_resume_lowercase.mp4");
    client->SetStartPos(100);
    client->SetDownloadedSize(0);
    client->SetResponseHeader("content-range", "bytes 100-199/200");

    bool result = client->HandleRangeResume(client->GetContext().get(), client.get());
    EXPECT_TRUE(result);
    EXPECT_EQ(client->GetStartPosValue(), 100);
}

HWTEST_F(NetworkClientExtTest, HandleRangeResume_UpperCaseContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    (void)client->SetOutputPath(testDir_ + "/range_resume_uppercase.mp4");
    client->SetStartPos(100);
    client->SetDownloadedSize(0);
    client->SetResponseHeader("CONTENT-RANGE", "bytes 100-199/200");

    bool result = client->HandleRangeResume(client->GetContext().get(), client.get());
    EXPECT_TRUE(result);
    EXPECT_EQ(client->GetStartPosValue(), 100);
}

HWTEST_F(NetworkClientExtTest, HandleRangeResume_MixedCaseContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    (void)client->SetOutputPath(testDir_ + "/range_resume_mixedcase.mp4");
    client->SetStartPos(100);
    client->SetDownloadedSize(0);
    client->SetResponseHeader("Content-range", "bytes 100-199/200");

    bool result = client->HandleRangeResume(client->GetContext().get(), client.get());
    EXPECT_TRUE(result);
    EXPECT_EQ(client->GetStartPosValue(), 100);
}

HWTEST_F(NetworkClientExtTest, ProcessHttp416RangeNotSatisfiable_LowerCaseContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    client->SetStartPos(2048);
    (void)client->SetOutputPath(testDir_ + "/process416_lowercase.mp4");
    client->SetResponseHeader("content-range", "bytes 1024-2047/2048");

    client->ProcessHttp416RangeNotSatisfiable();

    auto ctx = client->GetContext();
    EXPECT_TRUE(ctx->requestSuccess.load());
    EXPECT_EQ(ctx->totalSize.load(), 2048);
}

HWTEST_F(NetworkClientExtTest, ProcessHttp416RangeNotSatisfiable_UpperCaseContentRange_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    client->SetStartPos(2048);
    (void)client->SetOutputPath(testDir_ + "/process416_uppercase.mp4");
    client->SetResponseHeader("CONTENT-RANGE", "bytes 1024-2047/2048");

    client->ProcessHttp416RangeNotSatisfiable();

    auto ctx = client->GetContext();
    EXPECT_TRUE(ctx->requestSuccess.load());
    EXPECT_EQ(ctx->totalSize.load(), 2048);
}

HWTEST_F(NetworkClientExtTest, RxHeaderCallback_NormalizesHeaderKeyToLowerCase_001, TestSize.Level0)
{
    std::string url = "http://example.com/test.mp4";
    std::map<std::string, std::string> header;
    auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);

    auto ctx = client->GetContext();
    ctx->httpStatusCode.store(206);

    std::string headerLine = "Content-Range: bytes 0-99/1024\r\n";
    size_t result = TestableNetworkClient::RxHeaderCallback(
        headerLine.data(), 1, headerLine.size(), ctx.get());

    EXPECT_EQ(result, headerLine.size());

    auto it = ctx->responseHeaders.find("content-range");
    EXPECT_NE(it, ctx->responseHeaders.end());
    if (it != ctx->responseHeaders.end()) {
        EXPECT_EQ(it->second, "bytes 0-99/1024");
    }
}

HWTEST_F(NetworkClientExtTest, SetOutputPath_EmptyPath_001, TestSize.Level0)
    {
        std::string url = "http://example.com/test.mp4";
        std::map<std::string, std::string> header;
        auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
        int32_t ret = client->SetOutputPath("");
        EXPECT_NE(ret, DOWNLOAD_RET_OK);
    }

    HWTEST_F(NetworkClientExtTest, SetOutputPath_PathTraversal_001, TestSize.Level0)
    {
        std::string url = "http://example.com/test.mp4";
        std::map<std::string, std::string> header;
        auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
        int32_t ret = client->SetOutputPath("/data/../etc/passwd");
        EXPECT_NE(ret, DOWNLOAD_RET_OK);
    }

    HWTEST_F(NetworkClientExtTest, SetOutputPath_RelativePath_001, TestSize.Level0)
    {
        std::string url = "http://example.com/test.mp4";
        std::map<std::string, std::string> header;
        auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
        int32_t ret = client->SetOutputPath("relative/path.mp4");
        EXPECT_NE(ret, DOWNLOAD_RET_OK);
    }

    HWTEST_F(NetworkClientExtTest, SetOutputPath_ValidAbsolute_001, TestSize.Level0)
    {
        std::string url = "http://example.com/test.mp4";
        std::map<std::string, std::string> header;
        auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
        int32_t ret = client->SetOutputPath(testDir_ + "/valid_path_test.mp4");
        EXPECT_EQ(ret, DOWNLOAD_RET_OK);
        auto ctx = client->GetContext();
        EXPECT_EQ(ctx->outputPath, testDir_ + "/valid_path_test.mp4");
    }

    HWTEST_F(NetworkClientExtTest, SetOutputPath_ResumeValid_001, TestSize.Level0)
    {
        std::string url = "http://example.com/test.mp4";
        std::map<std::string, std::string> header;
        auto client = std::make_unique<TestableNetworkClient>(url, header, 30000, 3);
        std::string filePath = testDir_ + "/resume_valid_test.mp4";
        int32_t ret = client->SetOutputPath(filePath, 100);
        EXPECT_EQ(ret, DOWNLOAD_RET_OK);
        EXPECT_GE(client->GetOutputFd(), 0);
    }

} // namespace MediaDownload
} // namespace Media
} // namespace OHOS

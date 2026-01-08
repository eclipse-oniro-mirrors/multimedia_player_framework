/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fcntl.h>
#include <fstream>
#include "avmedia_source.h"
#include "avmediasource_unit_test.h"
#include "native_media_source_impl.h"
#include "native_player_magic.h"
#include "native_mfmagic.h"
#include "gtest/gtest.h"
#include "media_errors.h"
#include "loading_request_mock.h"
#include "native_media_source_loading_request_impl.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;

static const string TEST_FILE_PATH = "/data/test/media/test_264_B_Gop25_4sec_cover.mp4";

void NativeAVMediaSourceUnitTest::SetUpTestCase(void) {}

void NativeAVMediaSourceUnitTest::TearDownTestCase(void) {}

void NativeAVMediaSourceUnitTest::SetUp(void) {}

void NativeAVMediaSourceUnitTest::TearDown(void) {}

static int32_t AVSourceReadAt(OH_AVBuffer *data, int32_t length, int64_t pos)
{
    if (data == nullptr) {
        printf("AVSourceReadAt : data is nullptr!\n");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;
    }

    std::ifstream infile(TEST_FILE_PATH, std::ofstream::binary);
    if (!infile.is_open()) {
        printf("AVSourceReadAt : open file failed! file:%s\n", TEST_FILE_PATH.c_str());
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;  // 打开文件失败
    }

    infile.seekg(0, std::ios::end);
    int64_t fileSize = infile.tellg();
    if (pos >= fileSize) {
        printf("AVSourceReadAt : pos over or equals file size!\n");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_EOF;  // pos已经是文件末尾位置，无法读取
    }

    if (pos + length > fileSize) {
        length = fileSize - pos;    // pos+length长度超过文件大小时，读取从pos到文件末尾的数据
    }

    infile.seekg(pos, std::ios::beg);
    if (length <= 0) {
        printf("AVSourceReadAt : raed length less than zero!\n");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;
    }
    char* buffer = new char[length];
    infile.read(buffer, length);
    infile.close();

    errno_t result = memcpy_s(reinterpret_cast<char *>(OH_AVBuffer_GetAddr(data)),
        OH_AVBuffer_GetCapacity(data), buffer, length);
    delete[] buffer;
    if (result != 0) {
        printf("memcpy_s failed!");
        return OHOS::Media::MediaDataSourceError::SOURCE_ERROR_IO;
    }

    return length;
}

int64_t GetFileSize(const string &fileName)
{
    int64_t fileSize = 0;
    if (!fileName.empty()) {
        struct stat fileStatus {};
        if (stat(fileName.c_str(), &fileStatus) == 0) {
            fileSize = static_cast<int64_t>(fileStatus.st_size);
        }
    }
    return fileSize;
}

/**
 * @tc.name: AVMediaSource_SetMimeType_0100
 * @tc.desc: Test set mime type
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_SetMimeType_0100, Level2)
{
    const char *url = "http://example.com/video.mp4";
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    OH_AVMediaSource *mediasource = OH_AVMediaSource_CreateWithUrl(url, header);
    ASSERT_NE(mediasource, nullptr);
    const char *mimeType = "application/m3u8";
    int32_t ret = OH_AVMediaSource_SetMimeType(mediasource, mimeType);
    ASSERT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: AVMediaSource_SetMimeType_0200
 * @tc.desc: Test set mime type with invalid parameter
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_SetMimeType_0200, Level2)
{
    const char *mimeType = "video/mp4";
    int32_t ret = OH_AVMediaSource_SetMimeType(nullptr, const_cast<char*>(mimeType));
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: AVMediaSource_SetMimeType_0300
 * @tc.desc: Test set mime type with empty mime type
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_SetMimeType_0300, Level2)
{
    const char *url = "http://example.com/video.mp4";
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    OH_AVMediaSource *mediasource = OH_AVMediaSource_CreateWithUrl(url, header);
    ASSERT_NE(mediasource, nullptr);
    int32_t ret = OH_AVMediaSource_SetMimeType(mediasource, nullptr);
    ASSERT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: AVMediaSource_CreateWithUrl_0100
 * @tc.desc: Test create mediasource with url
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_CreateWithUrl_0100, Level2)
{
    const char *url = "http://example.com/video.mp4";
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    OH_AVMediaSource *mediasource = OH_AVMediaSource_CreateWithUrl(url, header);
    ASSERT_NE(mediasource, nullptr);
}

/**
 * @tc.name: AVMediaSource_CreateWithUrl_0200
 * @tc.desc: Test create mediasource with url with invalid parameter
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_CreateWithUrl_0200, Level2)
{
    const char *url = "http://example.com/video.mp4";
    OH_AVMediaSource *mediasource = OH_AVMediaSource_CreateWithUrl(url, nullptr);
    ASSERT_EQ(mediasource, nullptr);
}

/**
 * @tc.name: AVMediaSource_CreateWithUrl_0300
 * @tc.desc: Test create mediasource with empty url
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_CreateWithUrl_0300, Level2)
{
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    OH_AVMediaSource *mediasource = OH_AVMediaSource_CreateWithUrl(nullptr, header);
    ASSERT_EQ(mediasource, nullptr);
}

/**
 * @tc.name: AVMediaSource_CreateWithDataSource_0100
 * @tc.desc: Test create mediasource with dataSource
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_CreateWithDataSource_0100, Level2)
{
    int64_t size = GetFileSize(TEST_FILE_PATH);
    OH_AVDataSource dataSource = {size, AVSourceReadAt};

    OH_AVMediaSource *source = OH_AVMediaSource_CreateWithDataSource(&dataSource);
    ASSERT_NE(source, nullptr);
}

/**
 * @tc.name: AVMediaSource_CreateWithDataSource_0200
 * @tc.desc: Test create mediasource with empty dataSource
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_CreateWithDataSource_0200, Level2)
{
    OH_AVMediaSource *source = OH_AVMediaSource_CreateWithDataSource(nullptr);
    ASSERT_EQ(source, nullptr);
}

/**
 * @tc.name: AVMediaSource_CreateWithDataSource_0300
 * @tc.desc: Test create mediasource with dataSource with invalid parameter
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_CreateWithDataSource_0300, Level2)
{
    int64_t size = GetFileSize(TEST_FILE_PATH);
    OH_AVDataSource dataSource = {size, nullptr};

    OH_AVMediaSource *source = OH_AVMediaSource_CreateWithDataSource(&dataSource);
    ASSERT_EQ(source, nullptr);
}

/**
 * @tc.name: AVMediaSource_CreateWithFd_0100
 * @tc.desc: Test create mediasource with fd
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_CreateWithFd_0100, Level2)
{
    int32_t fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    int64_t offset = 0;
    int64_t size = GetFileSize(TEST_FILE_PATH);

    OH_AVMediaSource *source = OH_AVMediaSource_CreateWithFd(fd, offset, size);
    ASSERT_NE(source, nullptr);
}

/**
 * @tc.name: AVMediaSource_CreateWithFd_0200
 * @tc.desc: Test create mediasource with fd with invalid parameter
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_CreateWithFd_0200, Level2)
{
    int32_t fd = 0;
    int64_t offset = 0;
    int64_t size = 0;

    OH_AVMediaSource *source = OH_AVMediaSource_CreateWithFd(fd, offset, size);
    ASSERT_NE(source, nullptr);
}

/**
 * @tc.name: AVMediaSource_CreateWithFd_0300
 * @tc.desc: Test create mediasource with empty fd
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSource_CreateWithFd_0300, Level2)
{
    int32_t fd = open(TEST_FILE_PATH.c_str(), O_RDONLY);
    int64_t offset = 999999;
    int64_t size = GetFileSize(TEST_FILE_PATH);

    OH_AVMediaSource *source = OH_AVMediaSource_CreateWithFd(fd, offset, size);
    ASSERT_NE(source, nullptr);
}

/**
 * @tc.name: AVHttpHeader_Basic_0100
 * @tc.desc: Test create, add record, get count, get record and destroy of AVHttpHeader
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_0100, Level2)
{
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);

    OH_AVErrCode ret = OH_AVHttpHeader_AddRecord(header, "User-Agent", "TestAgent");
    ASSERT_EQ(ret, AV_ERR_OK);

    uint32_t count = 0;
    ret = OH_AVHttpHeader_GetCount(header, &count);
    ASSERT_EQ(ret, AV_ERR_OK);
    ASSERT_EQ(count, 1);

    const char *key = nullptr;
    const char *value = nullptr;
    ret = OH_AVHttpHeader_GetRecord(header, 0, &key, &value);
    ASSERT_EQ(ret, AV_ERR_OK);
    ASSERT_STREQ(key, "User-Agent");
    ASSERT_STREQ(value, "TestAgent");

    ret = OH_AVHttpHeader_Destroy(header);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: AVHttpHeader_Basic_0200
 * @tc.desc: Test get record of AVHttpHeader with invalid index
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_0200, Level2)
{
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    const char *key = nullptr;
    const char *value = nullptr;
    int32_t ret = OH_AVHttpHeader_GetRecord(header, 0, &key, &value);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = OH_AVHttpHeader_Destroy(header);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: AVHttpHeader_Basic_0300
 * @tc.desc: Test add record of AVHttpHeader with duplicate key
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_0300, Level2)
{
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    int32_t ret = OH_AVHttpHeader_AddRecord(header, "User-Agent", "TestAgent");
    ASSERT_EQ(ret, AV_ERR_OK);
    ret = OH_AVHttpHeader_AddRecord(header, "User-Agent", "AnotherAgent");
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = OH_AVHttpHeader_Destroy(header);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: AVHttpHeader_Basic_0400
 * @tc.desc: Test GetCount of AVHttpHeader with null count pointer
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_0400, Level2)
{
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    int32_t ret = OH_AVHttpHeader_GetCount(header, nullptr);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = OH_AVHttpHeader_Destroy(header);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: AVHttpHeader_Basic_0500
 * @tc.desc: Test AddRecord of AVHttpHeader with empty key and context
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_0500, Level2)
{
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    int32_t ret = OH_AVHttpHeader_AddRecord(header, "", "TestAgent");
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = OH_AVHttpHeader_AddRecord(header, "User-Agent", "");
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = OH_AVHttpHeader_Destroy(header);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: AVHttpHeader_Basic_0600
 * @tc.desc: Test GetRecord of AVHttpHeader with null key and value pointers
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_0600, Level2)
{
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(header, nullptr);
    int32_t ret = OH_AVHttpHeader_AddRecord(header, "User-Agent", "TestAgent");
    ASSERT_EQ(ret, AV_ERR_OK);
    ret = OH_AVHttpHeader_GetRecord(header, 0, nullptr, nullptr);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
    ret = OH_AVHttpHeader_Destroy(header);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: AVHttpHeader_Basic_0700
 * @tc.desc: Test AddRecord with nullptr header
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_0700, Level2)
{
    int32_t ret = OH_AVHttpHeader_AddRecord(nullptr, "User-Agent", "TestAgent");
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
}

/**
 * @tc.name: AVHttpHeader_Basic_0800
 * @tc.desc: Test GetCount with nullptr header
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_0800, Level2)
{
    uint32_t count = 0;
    OH_AVErrCode ret = OH_AVHttpHeader_GetCount(nullptr, &count);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
}

/**
 * @tc.name: AVHttpHeader_Basic_0900
 * @tc.desc: Test GetRecord with nullptr header
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_0900, Level2)
{
    const char *key = nullptr;
    const char *value = nullptr;
    int32_t ret = OH_AVHttpHeader_GetRecord(nullptr, 0, &key, &value);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
}

/**
 * @tc.name: AVHttpHeader_Basic_1000
 * @tc.desc: Test Destroy with nullptr header
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVHttpHeader_Basic_1000, Level2)
{
    int32_t ret = OH_AVHttpHeader_Destroy(nullptr);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_GetUrl_001
 * @tc.desc: Test get url from loading request
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSourceLoadingRequest_GetUrl_001, TestSize.Level1)
{
    std::string testUrl = "http://example.com/test.m3u8";
    std::map<std::string, std::string> header = {
        {"User-Agent", "TestAgent"},
        {"Accept", "*/*"}
    };
    auto request = std::make_shared<LoadingRequestMock>(testUrl, header);
    auto *requestObj = new MediaSourceLoadingRequestObject(request);
    OH_AVMediaSourceLoadingRequest *ndkRequest = reinterpret_cast<OH_AVMediaSourceLoadingRequest *>(requestObj);
    ASSERT_NE(ndkRequest, nullptr);

    const char *url = nullptr;
    OH_AVErrCode ret = OH_AVMediaSourceLoadingRequest_GetUrl(ndkRequest, &url);
    ASSERT_EQ(ret, AV_ERR_OK);
    ASSERT_NE(url, nullptr);
    ASSERT_STREQ(url, testUrl.c_str());
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_GetUrl_002
 * @tc.desc: Test get url from loading request with invalid parameter
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSourceLoadingRequest_GetUrl_002, TestSize.Level1)
{
    const char *url = nullptr;
    OH_AVErrCode ret = OH_AVMediaSourceLoadingRequest_GetUrl(nullptr, &url);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
    ASSERT_EQ(url, nullptr);
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_GetHttpHeader_001
 * @tc.desc: Test get header from loading request
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSourceLoadingRequest_GetHttpHeader_001, TestSize.Level1)
{
    std::string testUrl = "http://example.com/test.m3u8";
    std::map<std::string, std::string> header = {
        {"User-Agent", "TestAgent"},
        {"Accept", "*/*"}
    };
    auto request = std::make_shared<LoadingRequestMock>(testUrl, header);
    auto *requestObj = new MediaSourceLoadingRequestObject(request);
    OH_AVMediaSourceLoadingRequest *ndkRequest = reinterpret_cast<OH_AVMediaSourceLoadingRequest *>(requestObj);
    ASSERT_NE(ndkRequest, nullptr);

    OH_AVHttpHeader *ndkHeader = nullptr;
    OH_AVErrCode ret = OH_AVMediaSourceLoadingRequest_GetHttpHeader(ndkRequest, &ndkHeader);
    ASSERT_EQ(ret, AV_ERR_OK);
    ASSERT_NE(ndkHeader, nullptr);

    uint32_t count = 0;
    ret = OH_AVHttpHeader_GetCount(ndkHeader, &count);
    ASSERT_EQ(ret, AV_ERR_OK);
    ASSERT_EQ(count, static_cast<int32_t>(header.size()));
    for (int32_t i = 0; i < count; ++i) {
        const char *key = nullptr;
        const char *value = nullptr;
        OH_AVHttpHeader_GetRecord(ndkHeader, i, &key, &value);
        ASSERT_NE(key, nullptr);
        ASSERT_NE(value, nullptr);
        auto it = header.find(std::string(key));
        ASSERT_NE(it, header.end());
        ASSERT_STREQ(it->second.c_str(), value);
    }
    ret = OH_AVHttpHeader_Destroy(ndkHeader);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_GetHttpHeader_002
 * @tc.desc: Test get header from loading request with invalid parameter
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSourceLoadingRequest_GetHttpHeader_002, TestSize.Level1)
{
    OH_AVHttpHeader *ndkHeader = nullptr;
    OH_AVErrCode ret = OH_AVMediaSourceLoadingRequest_GetHttpHeader(nullptr, &ndkHeader);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
    ASSERT_EQ(ndkHeader, nullptr);
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_RespondData_001
 * @tc.desc: Test respond data
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoadingRequest_RespondData_001, TestSize.Level1)
{
    std::string testUrl = "http://example.com/test.m3u8";
    std::map<std::string, std::string> header = {
        {"User-Agent", "TestAgent"},
        {"Accept", "*/*"}
    };
    auto request = std::make_shared<LoadingRequestMock>(testUrl, header);
    auto *requestObj = new MediaSourceLoadingRequestObject(request);
    OH_AVMediaSourceLoadingRequest *ndkRequest = reinterpret_cast<OH_AVMediaSourceLoadingRequest *>(requestObj);
    ASSERT_NE(ndkRequest, nullptr);
    int64_t uuid = 12345;
    int64_t offset = 0;
    uint8_t testData[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint64_t dataSize = sizeof(testData);
    int32_t ret = OH_AVMediaSourceLoadingRequest_RespondData(ndkRequest, uuid, offset, testData, dataSize);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_RespondData_002
 * @tc.desc: Test respond data with invalid parameter
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSourceLoadingRequest_RespondData_002, TestSize.Level1)
{
    int32_t ret = OH_AVMediaSourceLoadingRequest_RespondData(nullptr, 12345, 0, nullptr, 0);
    ASSERT_EQ(ret, -1);
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_RespondData_003
 * @tc.desc: Test respond data with invalid dataSize
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSourceLoadingRequest_RespondData_003, TestSize.Level1)
{
    std::string testUrl = "http://example.com/test.m3u8";
    std::map<std::string, std::string> header = {
        {"User-Agent", "TestAgent"},
        {"Accept", "*/*"}
    };
    auto request = std::make_shared<LoadingRequestMock>(testUrl, header);
    auto *requestObj = new MediaSourceLoadingRequestObject(request);
    OH_AVMediaSourceLoadingRequest *ndkRequest = reinterpret_cast<OH_AVMediaSourceLoadingRequest *>(requestObj);
    ASSERT_NE(ndkRequest, nullptr);
    int64_t uuid = 12345;
    int64_t offset = 0;
    uint8_t testData[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint64_t dataSize = static_cast<uint64_t>(INT32_MAX) + 1;
    int32_t ret = OH_AVMediaSourceLoadingRequest_RespondData(ndkRequest, uuid, offset, testData, dataSize);
    ASSERT_EQ(ret, -1);
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_RespondHeader_001
 * @tc.desc: Test respond header
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSourceLoadingRequest_RespondHeader_001, TestSize.Level1)
{
    std::string testUrl = "http://example.com/test.m3u8";
    std::map<std::string, std::string> header = {
        {"User-Agent", "TestAgent"},
        {"Accept", "*/*"}
    };
    auto request = std::make_shared<LoadingRequestMock>(testUrl, header);
    request->respondHeaderCalled = false;
    auto *requestObj = new MediaSourceLoadingRequestObject(request);
    OH_AVMediaSourceLoadingRequest *ndkRequest = reinterpret_cast<OH_AVMediaSourceLoadingRequest *>(requestObj);
    ASSERT_NE(ndkRequest, nullptr);
    int64_t uuid = 12345;
    std::map<std::string, std::string> responseHeader = {
        {"Content-Type", "application/vnd.apple.mpegurl"},
        {"Content-Length", "1024"}
    };
    std::string redirectUrl = "http://example.com/redirect.m3u8";
    OH_AVHttpHeader *ndkResponseHeader = OH_AVHttpHeader_Create();
    ASSERT_NE(ndkResponseHeader, nullptr);
    OH_AVHttpHeader_AddRecord(ndkResponseHeader, "Content-Type", "application/vnd.apple.mpegurl");
    OH_AVHttpHeader_AddRecord(ndkResponseHeader, "Content-Length", "1024");
    OH_AVMediaSourceLoadingRequest_RespondHeader(ndkRequest, uuid, ndkResponseHeader, redirectUrl.c_str());
    ASSERT_TRUE(request->respondHeaderCalled);
    auto ret = OH_AVHttpHeader_Destroy(ndkResponseHeader);
    ASSERT_EQ(ret, AV_ERR_OK);
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_RespondHeader_002
 * @tc.desc: Test respond header with nullptr header
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSourceLoadingRequest_RespondHeader_002, TestSize.Level1)
{
    std::string testUrl = "http://example.com/test.m3u8";
    std::map<std::string, std::string> header = {
        {"User-Agent", "TestAgent"},
        {"Accept", "*/*"}
    };
    auto request = std::make_shared<LoadingRequestMock>(testUrl, header);
    request->respondHeaderCalled = false;
    auto *requestObj = new MediaSourceLoadingRequestObject(request);
    OH_AVMediaSourceLoadingRequest *ndkRequest = reinterpret_cast<OH_AVMediaSourceLoadingRequest *>(requestObj);
    ASSERT_NE(ndkRequest, nullptr);
    int64_t uuid = 12345;
    std::map<std::string, std::string> responseHeader = {
        {"Content-Type", "application/vnd.apple.mpegurl"},
        {"Content-Length", "1024"}
    };
    std::string redirectUrl = "http://example.com/redirect.m3u8";
    OH_AVHttpHeader *ndkResponseHeader = nullptr;
    OH_AVMediaSourceLoadingRequest_RespondHeader(ndkRequest, uuid, ndkResponseHeader, redirectUrl.c_str());
    ASSERT_TRUE(request->respondHeaderCalled);
    auto ret = OH_AVHttpHeader_Destroy(ndkResponseHeader);
    ASSERT_EQ(ret, AV_ERR_INVALID_VAL);
}

/**
 * @tc.name: AVMediaSourceLoadingRequest_FinishLoading_001
 * @tc.desc: Test finish loading
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, AVMediaSourceLoadingRequest_FinishLoading_001, TestSize.Level1)
{
    std::string testUrl = "http://example.com/test.m3u8";
    std::map<std::string, std::string> header = {
        {"User-Agent", "TestAgent"},
        {"Accept", "*/*"}
    };
    auto request = std::make_shared<LoadingRequestMock>(testUrl, header);
    request->finishLoadingCalled = false;
    auto *requestObj = new MediaSourceLoadingRequestObject(request);
    OH_AVMediaSourceLoadingRequest *ndkRequest = reinterpret_cast<OH_AVMediaSourceLoadingRequest *>(requestObj);
    ASSERT_NE(ndkRequest, nullptr);
    int64_t uuid = 12345;
    AVLoadingRequestError requestedError = AVLoadingRequestError::AV_LOADING_ERROR_SUCCESS;
    OH_AVMediaSourceLoadingRequest_FinishLoading(ndkRequest, uuid, requestedError);
    ASSERT_TRUE(request->finishLoadingCalled);
}

/**
 * @tc.name: OH_AVMediaSourceLoader_Create_0001
 * @tc.desc: Test create a mediasource loader object
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_Create_001, Level0)
{
    OH_AVMediaSourceLoader *loader = nullptr;
    loader = OH_AVMediaSourceLoader_Create();

    ASSERT_NE(nullptr, loader);
    OH_AVMediaSourceLoader_Destroy(loader);
}

int64_t SourceOpenCallbackFunc(OH_AVMediaSourceLoadingRequest *request, void *userData)
{
    return 0;
}

/**
 * @tc.name: OH_AVMediaSourceLoader_SetSourceOpenCallback_001
 * @tc.desc: Test set source open callback
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_SetSourceOpenCallback_001, Level0)
{
    OH_AVMediaSourceLoader *loader = OH_AVMediaSourceLoader_Create();
    ASSERT_NE(nullptr, loader);

    OH_AVErrCode ret = OH_AVMediaSourceLoader_SetSourceOpenCallback(loader, SourceOpenCallbackFunc, nullptr);
    EXPECT_EQ(AV_ERR_OK, ret);
    OH_AVMediaSourceLoader_Destroy(loader);
}

/**
 * @tc.name: OH_AVMediaSourceLoader_SetSourceOpenCallback_002
 * @tc.desc: Test set source open callback
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_SetSourceOpenCallback_002, Level0)
{
    OH_AVMediaSourceLoader *loader = OH_AVMediaSourceLoader_Create();
    ASSERT_NE(nullptr, loader);

    OH_AVErrCode ret = OH_AVMediaSourceLoader_SetSourceOpenCallback(loader, nullptr, nullptr);
    EXPECT_EQ(AV_ERR_OK, ret);
    OH_AVMediaSourceLoader_Destroy(loader);
}

/**
 * @tc.name: OH_AVMediaSourceLoader_SetSourceOpenCallback_003
 * @tc.desc: Test set source open callback
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_SetSourceOpenCallback_003, Level1)
{
    OH_AVErrCode ret = OH_AVMediaSourceLoader_SetSourceOpenCallback(nullptr, SourceOpenCallbackFunc, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, ret);
}

void SourceReadCallbackFunc(int64_t uuid, int64_t requestedOffset, int64_t requestedLength, void *userData)
{
    return;
}

/**
 * @tc.name: OH_AVMediaSourceLoader_SetSourceReadCallback_001
 * @tc.desc: Test set source read callback
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_SetSourceReadCallback_001, Level0)
{
    OH_AVMediaSourceLoader *loader = OH_AVMediaSourceLoader_Create();
    ASSERT_NE(nullptr, loader);

    OH_AVErrCode ret = OH_AVMediaSourceLoader_SetSourceReadCallback(loader, SourceReadCallbackFunc, nullptr);
    EXPECT_EQ(AV_ERR_OK, ret);
    OH_AVMediaSourceLoader_Destroy(loader);
}

/**
 * @tc.name: OH_AVMediaSourceLoader_SetSourceReadCallback_002
 * @tc.desc: Test set source read callback
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_SetSourceReadCallback_002, Level0)
{
    OH_AVMediaSourceLoader *loader = OH_AVMediaSourceLoader_Create();
    ASSERT_NE(nullptr, loader);

    OH_AVErrCode ret = OH_AVMediaSourceLoader_SetSourceReadCallback(loader, nullptr, nullptr);
    EXPECT_EQ(AV_ERR_OK, ret);
    OH_AVMediaSourceLoader_Destroy(loader);
}

/**
 * @tc.name: OH_AVMediaSourceLoader_SetSourceReadCallback_003
 * @tc.desc: Test set source read callback
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_SetSourceReadCallback_003, Level1)
{
    OH_AVErrCode ret = OH_AVMediaSourceLoader_SetSourceReadCallback(nullptr, SourceReadCallbackFunc, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, ret);
}

void SourceCloseCallbackFunc(int64_t uuid, void *userData)
{
    return;
}

/**
 * @tc.name: OH_AVMediaSourceLoader_SetSourceCloseCallback_001
 * @tc.desc: Test set source close callback
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_SetSourceCloseCallback_001, Level0)
{
    OH_AVMediaSourceLoader *loader = OH_AVMediaSourceLoader_Create();
    ASSERT_NE(nullptr, loader);

    OH_AVErrCode ret = OH_AVMediaSourceLoader_SetSourceCloseCallback(loader, SourceCloseCallbackFunc, nullptr);
    EXPECT_EQ(AV_ERR_OK, ret);
    OH_AVMediaSourceLoader_Destroy(loader);
}

/**
 * @tc.name: OH_AVMediaSourceLoader_SetSourceCloseCallback_002
 * @tc.desc: Test set source close callback by callback is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_SetSourceCloseCallback_002, Level0)
{
    OH_AVMediaSourceLoader *loader = OH_AVMediaSourceLoader_Create();
    ASSERT_NE(nullptr, loader);

    OH_AVErrCode ret = OH_AVMediaSourceLoader_SetSourceCloseCallback(loader, nullptr, nullptr);
    EXPECT_EQ(AV_ERR_OK, ret);
    OH_AVMediaSourceLoader_Destroy(loader);
}

/**
 * @tc.name: OH_AVMediaSourceLoader_SetSourceCloseCallback_003
 * @tc.desc: Test set source close callback by loader is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_SetSourceCloseCallback_003, Level1)
{
    OH_AVErrCode ret = OH_AVMediaSourceLoader_SetSourceCloseCallback(nullptr, SourceCloseCallbackFunc, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVMediaSourceLoader_Destroy_001
 * @tc.desc: Test release the mediasource loader object
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_Destroy_001, TestSize.Level0)
{
    OH_AVMediaSourceLoader *loader = OH_AVMediaSourceLoader_Create();
    ASSERT_NE(nullptr, loader);

    OH_AVErrCode ret = OH_AVMediaSourceLoader_Destroy(loader);
    EXPECT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVMediaSourceLoader_Destroy_002
 * @tc.desc: Test release the mediasource loader object by nullptr
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSourceLoader_Destroy_002, TestSize.Level1)
{
    OH_AVErrCode ret = OH_AVMediaSourceLoader_Destroy(nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVMediaSource_SetMediaSourceLoader_001
 * @tc.desc: Test set the mediasource loader object
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSource_SetMediaSourceLoader_001, TestSize.Level0)
{
    const char *url = "http://example.com/video.mp4";
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(nullptr, header);

    OH_AVMediaSource *mediasource = OH_AVMediaSource_CreateWithUrl(url, header);
    ASSERT_NE(nullptr, mediasource);

    OH_AVMediaSourceLoader *loader = OH_AVMediaSourceLoader_Create();
    ASSERT_NE(nullptr, loader);

    OH_AVErrCode ret = OH_AVMediaSource_SetMediaSourceLoader(mediasource, loader);
    EXPECT_EQ(AV_ERR_OK, ret);
}

/**
 * @tc.name: OH_AVMediaSource_SetMediaSourceLoader_002
 * @tc.desc: Test set the mediasource loader object by media source is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSource_SetMediaSourceLoader_002, TestSize.Level1)
{
    OH_AVMediaSourceLoader *loader = OH_AVMediaSourceLoader_Create();
    ASSERT_NE(nullptr, loader);

    OH_AVErrCode ret = OH_AVMediaSource_SetMediaSourceLoader(nullptr, loader);
    EXPECT_EQ(AV_ERR_INVALID_VAL, ret);
}

/**
 * @tc.name: OH_AVMediaSource_SetMediaSourceLoader_003
 * @tc.desc: Test set the mediasource loader object by loader is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(NativeAVMediaSourceUnitTest, OH_AVMediaSource_SetMediaSourceLoader_003, TestSize.Level1)
{
    const char *url = "http://example.com/video.mp4";
    OH_AVHttpHeader *header = OH_AVHttpHeader_Create();
    ASSERT_NE(nullptr, header);

    OH_AVMediaSource *mediasource = OH_AVMediaSource_CreateWithUrl(url, header);
    ASSERT_NE(nullptr, mediasource);

    OH_AVErrCode ret = OH_AVMediaSource_SetMediaSourceLoader(mediasource, nullptr);
    EXPECT_EQ(AV_ERR_INVALID_VAL, ret);
}

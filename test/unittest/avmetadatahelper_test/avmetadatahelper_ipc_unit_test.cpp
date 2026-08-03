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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <charconv>
#include <cstdint>
#include <new>
#include <string>
#include <string_view>
#include <vector>

#include "accesstoken_kit.h"
#include "avmetadatahelper_service_proxy.h"
#include "avmetadatahelper_service_stub.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "media_errors.h"
#include "media_permission.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
constexpr int32_t TEST_USAGE = 0;
constexpr int64_t TEST_OFFSET = 16;
constexpr int64_t TEST_SIZE = 128;
constexpr uid_t TEST_NON_ROOT_UID = 10000;
constexpr char READ_MEDIA_PERMISSION[] = "ohos.permission.READ_MEDIA";
constexpr std::string_view TOKEN_ID_KEY = "\"tokenID\": ";

uint64_t GetFoundationTokenId()
{
    Security::AccessToken::AtmToolsParamInfo info;
    info.processName = "foundation";
    std::string dumpInfo;
    Security::AccessToken::AccessTokenKit::DumpTokenInfo(info, dumpInfo);

    size_t tokenIdPos = dumpInfo.find(TOKEN_ID_KEY);
    if (tokenIdPos == std::string::npos) {
        return 0;
    }
    tokenIdPos += TOKEN_ID_KEY.size();
    uint64_t tokenId = 0;
    const char *begin = dumpInfo.data() + tokenIdPos;
    const char *end = dumpInfo.data() + dumpInfo.size();
    auto [ptr, ec] = std::from_chars(begin, end, tokenId);
    return ec == std::errc{} && ptr != begin ? tokenId : 0;
}

int32_t OpenTestFd()
{
    int32_t fd = open("/dev/null", O_RDONLY);
    if (fd < 0) {
        return fd;
    }
    int32_t testFd = fcntl(fd, F_DUPFD, 3);
    (void)close(fd);
    return testFd;
}

class ScopedFd {
public:
    explicit ScopedFd(int32_t fd) : fd_(fd) {}
    ~ScopedFd()
    {
        if (fd_ >= 0) {
            (void)close(fd_);
        }
    }

    ScopedFd(const ScopedFd &) = delete;
    ScopedFd &operator=(const ScopedFd &) = delete;

    int32_t Get() const
    {
        return fd_;
    }

private:
    int32_t fd_ = -1;
};

class ScopedNonRootUid {
public:
    ScopedNonRootUid()
    {
        originalUid_ = getuid();
        effectiveUid_ = geteuid();
        if (originalUid_ != 0) {
            valid_ = true;
            return;
        }
        if (effectiveUid_ != 0) {
            return;
        }
        changed_ = setreuid(TEST_NON_ROOT_UID, effectiveUid_) == 0;
        valid_ = changed_ && getuid() == TEST_NON_ROOT_UID;
    }

    ~ScopedNonRootUid()
    {
        if (changed_) {
            (void)setreuid(originalUid_, effectiveUid_);
        }
    }

    ScopedNonRootUid(const ScopedNonRootUid &) = delete;
    ScopedNonRootUid &operator=(const ScopedNonRootUid &) = delete;

    bool IsValid() const
    {
        return valid_;
    }

private:
    uid_t originalUid_ = 0;
    uid_t effectiveUid_ = 0;
    bool changed_ = false;
    bool valid_ = false;
};

class ScopedHapToken {
public:
    explicit ScopedHapToken(bool grantReadMedia)
    {
        oldTokenId_ = GetSelfTokenID();
        managerTokenId_ = GetFoundationTokenId();
        if (managerTokenId_ == 0 || SetSelfTokenID(managerTokenId_) != 0) {
            return;
        }
        Security::AccessToken::HapInfoParams info = {
            .userID = 100,
            .bundleName = grantReadMedia ? "com.ohos.test.avmetadata.read" : "com.ohos.test.avmetadata.denied",
            .instIndex = 0,
            .appIDDesc = "com.ohos.test.avmetadata.ipc",
            .apiVersion = 8,
            .isSystemApp = true
        };
        Security::AccessToken::HapPolicyParams policy = {
            .apl = Security::AccessToken::APL_SYSTEM_BASIC,
            .domain = "test.avmetadata.ipc",
            .permList = {},
            .permStateList = {}
        };
        if (grantReadMedia) {
            Security::AccessToken::PermissionStateFull readMediaState = {
                .permissionName = READ_MEDIA_PERMISSION,
                .isGeneral = true,
                .resDeviceID = { "local" },
                .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
                .grantFlags = { 1 }
            };
            policy.permStateList.emplace_back(readMediaState);
        }

        Security::AccessToken::AccessTokenIDEx tokenIdEx =
            Security::AccessToken::AccessTokenKit::AllocHapToken(info, policy);
        accessTokenId_ = tokenIdEx.tokenIdExStruct.tokenID;
        valid_ = accessTokenId_ != 0 && SetSelfTokenID(tokenIdEx.tokenIDEx) == 0 &&
            GetSelfTokenID() == tokenIdEx.tokenIDEx;
    }

    ~ScopedHapToken()
    {
        if (managerTokenId_ != 0 && SetSelfTokenID(managerTokenId_) == 0 && accessTokenId_ != 0) {
            (void)Security::AccessToken::AccessTokenKit::DeleteToken(accessTokenId_);
        }
        (void)SetSelfTokenID(oldTokenId_);
    }

    bool IsValid() const
    {
        return valid_;
    }

    Security::AccessToken::AccessTokenID GetTokenId() const
    {
        return accessTokenId_;
    }

private:
    uint64_t oldTokenId_ = 0;
    uint64_t managerTokenId_ = 0;
    Security::AccessToken::AccessTokenID accessTokenId_ = 0;
    bool valid_ = false;
};

class MockAVMetadataRemoteObject : public AVMetadataHelperServiceStub {
public:
    MOCK_METHOD(int, SendRequest, (uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option), (override));
};

class AVMetadataHelperServiceProxyUnitTest : public testing::Test {
public:
    void SetUp() override
    {
        mockRemote_ = new(std::nothrow) MockAVMetadataRemoteObject();
        ASSERT_NE(mockRemote_, nullptr);
        proxy_ = new(std::nothrow) AVMetadataHelperServiceProxy(mockRemote_);
        ASSERT_NE(proxy_, nullptr);
    }

    void TearDown() override
    {
        delete proxy_;
        proxy_ = nullptr;
        mockRemote_ = nullptr;
    }

protected:
    sptr<MockAVMetadataRemoteObject> mockRemote_;
    AVMetadataHelperServiceProxy *proxy_ = nullptr;
};

class AVMetadataHelperServiceStubUnitTest : public testing::Test {
public:
    void SetUp() override
    {
        stub_ = new(std::nothrow) AVMetadataHelperServiceStub();
        ASSERT_NE(stub_, nullptr);
        stub_->InitFunctionMap();
    }

    void TearDown() override
    {
        stub_ = nullptr;
    }

protected:
    int32_t SendUriSourceRequest(const std::string &uri)
    {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        EXPECT_TRUE(data.WriteInterfaceToken(AVMetadataHelperServiceStub::GetDescriptor()));
        EXPECT_TRUE(data.WriteString(uri));
        EXPECT_TRUE(data.WriteInt32(TEST_USAGE));
        int32_t ret = stub_->OnRemoteRequest(IStandardAVMetadataHelperService::SET_URI_SOURCE,
            data, reply, option);
        EXPECT_EQ(ret, MSERR_OK);
        return reply.ReadInt32();
    }

    sptr<AVMetadataHelperServiceStub> stub_;
};
} // namespace

/**
 * @tc.name: SetSource_FdUriWithRange_UsesFdIpc_001
 * @tc.desc: A fd URI is transferred through file descriptor IPC with its range parameters.
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServiceProxyUnitTest, SetSource_FdUriWithRange_UsesFdIpc_001, TestSize.Level0)
{
    ScopedFd sourceFd(OpenTestFd());
    ASSERT_GT(sourceFd.Get(), 0);
    std::string uri = "fd://" + std::to_string(sourceFd.Get()) + "?offset=" +
        std::to_string(TEST_OFFSET) + "&size=" + std::to_string(TEST_SIZE);

    EXPECT_CALL(*mockRemote_, SendRequest(IStandardAVMetadataHelperService::SET_FD_SOURCE, _, _, _))
        .WillOnce(Invoke([&](uint32_t, MessageParcel &data, MessageParcel &reply, MessageOption &) {
            EXPECT_EQ(data.ReadInterfaceToken(), AVMetadataHelperServiceProxy::GetDescriptor());
            int32_t transferredFd = data.ReadFileDescriptor();
            EXPECT_GE(transferredFd, 0);
            if (transferredFd >= 0) {
                struct stat sourceStat = {};
                struct stat transferredStat = {};
                EXPECT_EQ(fstat(sourceFd.Get(), &sourceStat), 0);
                EXPECT_EQ(fstat(transferredFd, &transferredStat), 0);
                EXPECT_EQ(sourceStat.st_dev, transferredStat.st_dev);
                EXPECT_EQ(sourceStat.st_ino, transferredStat.st_ino);
                (void)close(transferredFd);
            }
            EXPECT_EQ(data.ReadInt64(), TEST_OFFSET);
            EXPECT_EQ(data.ReadInt64(), TEST_SIZE);
            EXPECT_EQ(data.ReadInt32(), TEST_USAGE);
            EXPECT_TRUE(reply.WriteInt32(MSERR_OK));
            return MSERR_OK;
        }));

    EXPECT_EQ(proxy_->SetSource(uri, TEST_USAGE), MSERR_OK);
}

/**
 * @tc.name: SetSource_FdUriWithoutRange_UsesDefaults_001
 * @tc.desc: A fd URI without range parameters uses the fd IPC defaults.
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServiceProxyUnitTest, SetSource_FdUriWithoutRange_UsesDefaults_001, TestSize.Level0)
{
    ScopedFd sourceFd(OpenTestFd());
    ASSERT_GT(sourceFd.Get(), 0);
    std::string uri = "fd://" + std::to_string(sourceFd.Get());

    EXPECT_CALL(*mockRemote_, SendRequest(IStandardAVMetadataHelperService::SET_FD_SOURCE, _, _, _))
        .WillOnce(Invoke([](uint32_t, MessageParcel &data, MessageParcel &reply, MessageOption &) {
            (void)data.ReadInterfaceToken();
            int32_t transferredFd = data.ReadFileDescriptor();
            EXPECT_GE(transferredFd, 0);
            if (transferredFd >= 0) {
                (void)close(transferredFd);
            }
            EXPECT_EQ(data.ReadInt64(), 0);
            EXPECT_EQ(data.ReadInt64(), 0);
            EXPECT_EQ(data.ReadInt32(), TEST_USAGE);
            EXPECT_TRUE(reply.WriteInt32(MSERR_OK));
            return MSERR_OK;
        }));

    EXPECT_EQ(proxy_->SetSource(uri, TEST_USAGE), MSERR_OK);
}

/**
 * @tc.name: SetSource_FileUri_UsesUriIpc_001
 * @tc.desc: A non-fd URI continues to use the URI IPC transaction.
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServiceProxyUnitTest, SetSource_FileUri_UsesUriIpc_001, TestSize.Level0)
{
    const std::string uri = "file:///data/test/media.mp4";
    EXPECT_CALL(*mockRemote_, SendRequest(IStandardAVMetadataHelperService::SET_URI_SOURCE, _, _, _))
        .WillOnce(Invoke([&](uint32_t, MessageParcel &data, MessageParcel &reply, MessageOption &) {
            EXPECT_EQ(data.ReadInterfaceToken(), AVMetadataHelperServiceProxy::GetDescriptor());
            EXPECT_EQ(data.ReadString(), uri);
            EXPECT_EQ(data.ReadInt32(), TEST_USAGE);
            EXPECT_TRUE(reply.WriteInt32(MSERR_OK));
            return MSERR_OK;
        }));

    EXPECT_EQ(proxy_->SetSource(uri, TEST_USAGE), MSERR_OK);
}

/**
 * @tc.name: SetSource_InvalidFdUri_IsRejectedWithoutIpc_001
 * @tc.desc: Malformed fd URIs are rejected before any IPC transaction.
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServiceProxyUnitTest, SetSource_InvalidFdUri_IsRejectedWithoutIpc_001, TestSize.Level0)
{
    const std::vector<std::string> invalidUris = {
        "fd://",
        "fd://0",
        "fd://abc",
        "fd://2147483648",
        "fd://1?offset=0",
        "fd://1?offset=-1&size=1",
        "fd://1?offset=0&size=-2",
        "fd://1?offset=0&size=1tail"
    };
    EXPECT_CALL(*mockRemote_, SendRequest(_, _, _, _)).Times(0);
    for (const std::string &uri : invalidUris) {
        SCOPED_TRACE(uri);
        EXPECT_EQ(proxy_->SetSource(uri, TEST_USAGE), MSERR_INVALID_VAL);
    }
}

/**
 * @tc.name: SetUriSource_RawFdUri_IsRejected_001
 * @tc.desc: A handcrafted URI transaction cannot pass a numeric fd to the service.
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServiceStubUnitTest, SetUriSource_RawFdUri_IsRejected_001, TestSize.Level0)
{
    const std::vector<std::string> fdUris = {
        "fd://123?offset=0&size=128",
        "  fd://123?offset=0&size=128"
    };
    for (const std::string &uri : fdUris) {
        SCOPED_TRACE(uri);
        EXPECT_EQ(SendUriSourceRequest(uri), MSERR_INVALID_VAL);
    }
}

/**
 * @tc.name: SetUriSource_WithoutReadMediaPermission_IsDenied_001
 * @tc.desc: A handcrafted file URI transaction is rejected for a caller without READ_MEDIA.
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServiceStubUnitTest,
    SetUriSource_WithoutReadMediaPermission_IsDenied_001, TestSize.Level0)
{
    ScopedHapToken token(false);
    ASSERT_TRUE(token.IsValid());
    ScopedNonRootUid callerUid;
    ASSERT_TRUE(callerUid.IsValid());
    ASSERT_EQ(MediaPermission::CheckReadMediaPermission(),
        Security::AccessToken::PERMISSION_DENIED);
    EXPECT_EQ(SendUriSourceRequest("file:///data/test/secret.mp4"), MSERR_USER_NO_PERMISSION);
}

/**
 * @tc.name: SetUriSource_WithReadMediaPermission_PassesPermissionGate_001
 * @tc.desc: A caller with READ_MEDIA passes the permission gate before service dispatch.
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServiceStubUnitTest,
    SetUriSource_WithReadMediaPermission_PassesPermissionGate_001, TestSize.Level0)
{
    ScopedHapToken token(true);
    ASSERT_TRUE(token.IsValid());
    ScopedNonRootUid callerUid;
    ASSERT_TRUE(callerUid.IsValid());
    ASSERT_EQ(MediaPermission::CheckReadMediaPermission(),
        Security::AccessToken::PERMISSION_GRANTED);
    EXPECT_EQ(SendUriSourceRequest("file:///data/test/media.mp4"), MSERR_NO_MEMORY);
}

/**
 * @tc.name: SetFdSource_WithoutReadMediaPermission_UsesFdCapability_001
 * @tc.desc: A transferred fd remains a capability and does not require READ_MEDIA.
 * @tc.type: FUNC
 */
HWTEST_F(AVMetadataHelperServiceStubUnitTest,
    SetFdSource_WithoutReadMediaPermission_UsesFdCapability_001, TestSize.Level0)
{
    ScopedHapToken token(false);
    ASSERT_TRUE(token.IsValid());
    ASSERT_EQ(Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        token.GetTokenId(), READ_MEDIA_PERMISSION),
        Security::AccessToken::PERMISSION_DENIED);
    ScopedFd sourceFd(OpenTestFd());
    ASSERT_GT(sourceFd.Get(), 0);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(AVMetadataHelperServiceStub::GetDescriptor()));
    ASSERT_TRUE(data.WriteFileDescriptor(sourceFd.Get()));
    ASSERT_TRUE(data.WriteInt64(0));
    ASSERT_TRUE(data.WriteInt64(0));
    ASSERT_TRUE(data.WriteInt32(TEST_USAGE));
    EXPECT_EQ(stub_->OnRemoteRequest(IStandardAVMetadataHelperService::SET_FD_SOURCE,
        data, reply, option), MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
}
} // namespace Media
} // namespace OHOS

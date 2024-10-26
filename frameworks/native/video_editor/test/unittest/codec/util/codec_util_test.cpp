/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "codec/util/codec_util.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

class CodecUtilTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

// test CodecUtilTest_001
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_001, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_OK;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_OK");
}

// test CodecUtilTest_002
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_002, TestSize.Level0)
{
    OH_AVErrCode errorCode = static_cast<OH_AVErrCode>(-1);
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "?");
}

// test CodecUtilTest_003
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_003, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_NO_MEMORY;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_NO_MEMORY");
}

// test CodecUtilTest_004
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_004, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_OPERATE_NOT_PERMIT;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_OPERATE_NOT_PERMIT");
}

// test CodecUtilTest_005
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_005, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_INVALID_VAL;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_INVALID_VAL");
}

// test CodecUtilTest_006
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_006, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_IO;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_IO");
}

// test CodecUtilTest_007
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_007, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_TIMEOUT;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_TIMEOUT");
}

// test CodecUtilTest_008
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_008, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_UNKNOWN;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_UNKNOWN");
}

// test CodecUtilTest_009
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_009, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_SERVICE_DIED;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_SERVICE_DIED");
}

// test CodecUtilTest_010
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_010, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_INVALID_STATE;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_INVALID_STATE");
}

// test CodecUtilTest_011
HWTEST_F(CodecUtilTest, CodecUtil_GetCodecErrorStr_011, TestSize.Level0)
{
    OH_AVErrCode errorCode = AV_ERR_UNSUPPORT;
    const char* errorStr = CodecUtil::GetCodecErrorStr(errorCode);
    EXPECT_STREQ(errorStr, "AV_ERR_UNSUPPORT");
}
} // namespace Media
} // namespace OHOS
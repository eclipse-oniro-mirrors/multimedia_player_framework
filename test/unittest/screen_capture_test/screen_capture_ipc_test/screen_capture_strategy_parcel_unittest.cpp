/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "media_errors.h"
#include "media_log.h"
#include "screen_capture_ipc.h"

#include <gtest/gtest.h>
#include <memory>
#include <message_parcel.h>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

class ScreenCaptureStrategyParcelTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

HWTEST_F(ScreenCaptureStrategyParcelTest, MarshallingUnmarshalling_AllFields_001, TestSize.Level1)
{
    ScreenCaptureStrategyParcel src;
    src.strategy.enableDeviceLevelCapture = true;
    src.strategy.keepCaptureDuringCall = true;
    src.strategy.strategyForPrivacyMaskMode = 1;
    src.strategy.canvasFollowRotation = true;
    src.strategy.enableBFrame = true;
    src.strategy.pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    src.strategy.fillMode = AVScreenCaptureFillMode::SCALE_TO_FILL;
    src.strategy.enablePause = true;
    src.strategy.enableAEC = true;
    src.strategy.contentAutoPauseScenes = static_cast<uint32_t>(
        AVScreenCaptureAutoPauseScene::SCREEN_FOLD_STATE_CHANGE);

    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));

    std::unique_ptr<ScreenCaptureStrategyParcel> dst(ScreenCaptureStrategyParcel::Unmarshalling(parcel));
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(dst->strategy.enableDeviceLevelCapture, true);
    ASSERT_EQ(dst->strategy.keepCaptureDuringCall, true);
    ASSERT_EQ(dst->strategy.strategyForPrivacyMaskMode, 1);
    ASSERT_EQ(dst->strategy.canvasFollowRotation, true);
    ASSERT_EQ(dst->strategy.enableBFrame, true);
    ASSERT_EQ(dst->strategy.pickerPopUp, AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE);
    ASSERT_EQ(dst->strategy.fillMode, AVScreenCaptureFillMode::SCALE_TO_FILL);
    ASSERT_EQ(dst->strategy.enablePause, true);
    ASSERT_EQ(dst->strategy.enableAEC, true);
    ASSERT_EQ(dst->strategy.contentAutoPauseScenes,
        static_cast<uint32_t>(AVScreenCaptureAutoPauseScene::SCREEN_FOLD_STATE_CHANGE));
}

HWTEST_F(ScreenCaptureStrategyParcelTest, MarshallingUnmarshalling_DefaultValues_002, TestSize.Level1)
{
    ScreenCaptureStrategyParcel src;
    src.strategy.enableAEC = false;
    src.strategy.enableDeviceLevelCapture = false;
    src.strategy.keepCaptureDuringCall = false;
    src.strategy.enableBFrame = false;
    src.strategy.enablePause = false;

    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));

    std::unique_ptr<ScreenCaptureStrategyParcel> dst(ScreenCaptureStrategyParcel::Unmarshalling(parcel));
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(dst->strategy.enableAEC, false);
    ASSERT_EQ(dst->strategy.enableDeviceLevelCapture, false);
    ASSERT_EQ(dst->strategy.keepCaptureDuringCall, false);
    ASSERT_EQ(dst->strategy.enableBFrame, false);
    ASSERT_EQ(dst->strategy.enablePause, false);
}

HWTEST_F(ScreenCaptureStrategyParcelTest, Unmarshalling_EmptyParcel_ReturnsNull_001, TestSize.Level1)
{
    MessageParcel emptyParcel;
    std::unique_ptr<ScreenCaptureStrategyParcel> result(ScreenCaptureStrategyParcel::Unmarshalling(emptyParcel));
    ASSERT_EQ(result, nullptr);

    MessageParcel partialParcel;
    partialParcel.WriteBool(true);
    partialParcel.WriteBool(false);
    std::unique_ptr<ScreenCaptureStrategyParcel> partialResult(
        ScreenCaptureStrategyParcel::Unmarshalling(partialParcel));
    ASSERT_EQ(partialResult, nullptr);

    ScreenCaptureStrategyParcel src;
    src.strategy.enableAEC = true;
    MessageParcel validParcel;
    ASSERT_TRUE(src.Marshalling(validParcel));
    std::unique_ptr<ScreenCaptureStrategyParcel> validResult(ScreenCaptureStrategyParcel::Unmarshalling(validParcel));
    ASSERT_NE(validResult, nullptr);
    ASSERT_EQ(validResult->strategy.enableAEC, true);
}

// covers contentAutoPauseScenes bitmask round-trip: NONE(0) and SCREEN_FOLD_STATE_CHANGE(bit 0).
HWTEST_F(ScreenCaptureStrategyParcelTest, MarshallingUnmarshalling_ContentAutoPauseScenes_001, TestSize.Level1)
{
    ScreenCaptureStrategyParcel srcFold;
    srcFold.strategy.contentAutoPauseScenes = static_cast<uint32_t>(
        AVScreenCaptureAutoPauseScene::SCREEN_FOLD_STATE_CHANGE);
    MessageParcel parcelFold;
    ASSERT_TRUE(srcFold.Marshalling(parcelFold));
    std::unique_ptr<ScreenCaptureStrategyParcel> dstFold(ScreenCaptureStrategyParcel::Unmarshalling(parcelFold));
    ASSERT_NE(dstFold, nullptr);
    ASSERT_EQ(dstFold->strategy.contentAutoPauseScenes,
        static_cast<uint32_t>(AVScreenCaptureAutoPauseScene::SCREEN_FOLD_STATE_CHANGE));

    ScreenCaptureStrategyParcel srcNone;
    srcNone.strategy.contentAutoPauseScenes = static_cast<uint32_t>(AVScreenCaptureAutoPauseScene::NONE);
    MessageParcel parcelNone;
    ASSERT_TRUE(srcNone.Marshalling(parcelNone));
    std::unique_ptr<ScreenCaptureStrategyParcel> dstNone(ScreenCaptureStrategyParcel::Unmarshalling(parcelNone));
    ASSERT_NE(dstNone, nullptr);
    ASSERT_EQ(dstNone->strategy.contentAutoPauseScenes, static_cast<uint32_t>(AVScreenCaptureAutoPauseScene::NONE));
}

} // namespace Media
} // namespace OHOS

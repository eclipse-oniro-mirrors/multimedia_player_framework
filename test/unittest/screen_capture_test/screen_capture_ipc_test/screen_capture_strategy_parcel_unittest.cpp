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

#include "screen_capture_ipc.h"
#include "media_errors.h"
#include "media_log.h"

#include <gtest/gtest.h>
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
    src.enableDeviceLevelCapture = true;
    src.keepCaptureDuringCall = true;
    src.strategyForPrivacyMaskMode = 1;
    src.canvasFollowRotation = true;
    src.enableBFrame = true;
    src.pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    src.fillMode = AVScreenCaptureFillMode::SCALE_TO_FILL;
    src.enablePause = true;
    src.enableAEC = true;

    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));

    auto dst = ScreenCaptureStrategyParcel::Unmarshalling(parcel);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(dst->enableDeviceLevelCapture, true);
    ASSERT_EQ(dst->keepCaptureDuringCall, true);
    ASSERT_EQ(dst->strategyForPrivacyMaskMode, 1);
    ASSERT_EQ(dst->canvasFollowRotation, true);
    ASSERT_EQ(dst->enableBFrame, true);
    ASSERT_EQ(dst->pickerPopUp, AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE);
    ASSERT_EQ(dst->fillMode, AVScreenCaptureFillMode::SCALE_TO_FILL);
    ASSERT_EQ(dst->enablePause, true);
    ASSERT_EQ(dst->enableAEC, true);
}

HWTEST_F(ScreenCaptureStrategyParcelTest, MarshallingUnmarshalling_DefaultValues_002, TestSize.Level1)
{
    ScreenCaptureStrategyParcel src;
    src.enableAEC = false;
    src.enableDeviceLevelCapture = false;
    src.keepCaptureDuringCall = false;
    src.enableBFrame = false;
    src.enablePause = false;

    MessageParcel parcel;
    ASSERT_TRUE(src.Marshalling(parcel));

    auto dst = ScreenCaptureStrategyParcel::Unmarshalling(parcel);
    ASSERT_NE(dst, nullptr);
    ASSERT_EQ(dst->enableAEC, false);
    ASSERT_EQ(dst->enableDeviceLevelCapture, false);
    ASSERT_EQ(dst->keepCaptureDuringCall, false);
    ASSERT_EQ(dst->enableBFrame, false);
    ASSERT_EQ(dst->enablePause, false);
}

HWTEST_F(ScreenCaptureStrategyParcelTest, Unmarshalling_EmptyParcel_ReturnsNull_001, TestSize.Level1)
{
    MessageParcel emptyParcel;
    auto result = ScreenCaptureStrategyParcel::Unmarshalling(emptyParcel);
    ASSERT_EQ(result, nullptr);

    MessageParcel partialParcel;
    partialParcel.WriteBool(true);
    partialParcel.WriteBool(false);
    auto partialResult = ScreenCaptureStrategyParcel::Unmarshalling(partialParcel);
    ASSERT_EQ(partialResult, nullptr);

    ScreenCaptureStrategyParcel src;
    src.enableAEC = true;
    MessageParcel validParcel;
    ASSERT_TRUE(src.Marshalling(validParcel));
    auto validResult = ScreenCaptureStrategyParcel::Unmarshalling(validParcel);
    ASSERT_NE(validResult, nullptr);
    ASSERT_EQ(validResult->enableAEC, true);
}

// covers Unmarshalling: every Read short-circuit failure branch. Writes exactly N fields
// (N = 0..8); the (N+1)-th Read then fails and Unmarshalling must return nullptr. This
// exercises each ReadBool/ReadInt32 false branch, including the enableAEC read (N = 8).
// N = 9 writes all fields and confirms a successful round-trip of enableAEC.
HWTEST_F(ScreenCaptureStrategyParcelTest, Unmarshalling_PartialParcel_EachReadFails_001, TestSize.Level1)
{
    for (int32_t n = 0; n <= 9; ++n) {
        MessageParcel parcel;
        if (n >= 1) { parcel.WriteBool(true); }   // enableDeviceLevelCapture
        if (n >= 2) { parcel.WriteBool(true); }   // keepCaptureDuringCall
        if (n >= 3) { parcel.WriteInt32(1); }     // strategyForPrivacyMaskMode
        if (n >= 4) { parcel.WriteBool(true); }   // canvasFollowRotation
        if (n >= 5) { parcel.WriteBool(true); }   // enableBFrame
        if (n >= 6) { parcel.WriteInt32(0); }     // pickerPopUp
        if (n >= 7) { parcel.WriteInt32(0); }     // fillMode
        if (n >= 8) { parcel.WriteBool(true); }   // enablePause
        if (n >= 9) { parcel.WriteBool(true); }   // enableAEC
        auto dst = ScreenCaptureStrategyParcel::Unmarshalling(parcel);
        if (n < 9) {
            ASSERT_EQ(dst, nullptr) << "Unmarshalling should return null when only " << n << " fields are written";
        } else {
            ASSERT_NE(dst, nullptr);
            ASSERT_EQ(dst->enableAEC, true);
        }
    }
}

} // namespace Media
} // namespace OHOS

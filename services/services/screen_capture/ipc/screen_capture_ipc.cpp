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

#include "screen_capture_ipc.h"

namespace OHOS {
namespace Media {

bool ScreenCaptureStrategyParcel::Marshalling(Parcel &parcel) const
{
    return parcel.WriteBool(enableDeviceLevelCapture) && parcel.WriteBool(keepCaptureDuringCall) &&
        parcel.WriteInt32(strategyForPrivacyMaskMode) && parcel.WriteBool(canvasFollowRotation) &&
        parcel.WriteBool(enableBFrame) && parcel.WriteInt32(static_cast<int32_t>(pickerPopUp)) &&
        parcel.WriteInt32(static_cast<int32_t>(fillMode)) && parcel.WriteBool(enablePause) &&
        parcel.WriteBool(enableAEC);
}

sptr<ScreenCaptureStrategyParcel> ScreenCaptureStrategyParcel::Unmarshalling(Parcel &parcel)
{
    auto obj = sptr<ScreenCaptureStrategyParcel>::MakeSptr();
    int32_t pickerPopUpVal = 0;
    int32_t fillModeVal = 0;
    if (parcel.ReadBool(obj->enableDeviceLevelCapture) && parcel.ReadBool(obj->keepCaptureDuringCall) &&
        parcel.ReadInt32(obj->strategyForPrivacyMaskMode) && parcel.ReadBool(obj->canvasFollowRotation) &&
        parcel.ReadBool(obj->enableBFrame) && parcel.ReadInt32(pickerPopUpVal) && parcel.ReadInt32(fillModeVal) &&
        parcel.ReadBool(obj->enablePause) && parcel.ReadBool(obj->enableAEC)) {
        obj->pickerPopUp = static_cast<AVScreenCapturePickerPopUp>(pickerPopUpVal);
        obj->fillMode = static_cast<AVScreenCaptureFillMode>(fillModeVal);
        return obj;
    }
    return nullptr;
}

} // namespace Media
} // namespace OHOS

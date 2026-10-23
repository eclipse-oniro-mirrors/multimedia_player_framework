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
    return parcel.WriteBool(strategy.enableDeviceLevelCapture) && parcel.WriteBool(strategy.keepCaptureDuringCall) &&
        parcel.WriteInt32(strategy.strategyForPrivacyMaskMode) && parcel.WriteBool(strategy.canvasFollowRotation) &&
        parcel.WriteBool(strategy.enableBFrame) && parcel.WriteInt32(static_cast<int32_t>(strategy.pickerPopUp)) &&
        parcel.WriteInt32(static_cast<int32_t>(strategy.fillMode)) && parcel.WriteBool(strategy.enablePause) &&
        parcel.WriteBool(strategy.enableAEC) && parcel.WriteUint32(strategy.contentAutoPauseScenes) &&
        parcel.WriteBool(strategy.enableHDRCapture);
}

ScreenCaptureStrategyParcel *ScreenCaptureStrategyParcel::Unmarshalling(Parcel &parcel)
{
    auto obj = new ScreenCaptureStrategyParcel();
    int32_t pickerPopUpVal = 0;
    int32_t fillModeVal = 0;
    if (parcel.ReadBool(obj->strategy.enableDeviceLevelCapture) &&
        parcel.ReadBool(obj->strategy.keepCaptureDuringCall) &&
        parcel.ReadInt32(obj->strategy.strategyForPrivacyMaskMode) &&
        parcel.ReadBool(obj->strategy.canvasFollowRotation) && parcel.ReadBool(obj->strategy.enableBFrame) &&
        parcel.ReadInt32(pickerPopUpVal) && parcel.ReadInt32(fillModeVal) &&
        parcel.ReadBool(obj->strategy.enablePause) && parcel.ReadBool(obj->strategy.enableAEC) &&
        parcel.ReadUint32(obj->strategy.contentAutoPauseScenes) &&
        parcel.ReadBool(obj->strategy.enableHDRCapture)) {
        obj->strategy.pickerPopUp = static_cast<AVScreenCapturePickerPopUp>(pickerPopUpVal);
        obj->strategy.fillMode = static_cast<AVScreenCaptureFillMode>(fillModeVal);
        return obj;
    }
    delete obj;
    return nullptr;
}

} // namespace Media
} // namespace OHOS

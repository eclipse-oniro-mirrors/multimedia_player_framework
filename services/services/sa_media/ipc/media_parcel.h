/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef MEDIA_PARCEL_H
#define MEDIA_PARCEL_H

#include "meta/meta.h"
#include "meta/format.h"
#include "message_parcel.h"

namespace OHOS {
namespace Media {
class MediaParcel {
public:
    MediaParcel() = delete;
    ~MediaParcel() = delete;
    static bool Marshalling(MessageParcel &parcel, const Format &format);
    static bool Unmarshalling(MessageParcel &parcel, Format &format);
    static bool MetaMarshalling(MessageParcel &parcel, const Media::Format &format);
    static bool MetaUnmarshalling(MessageParcel &parcel, Media::Format &format);
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_PARCEL_H

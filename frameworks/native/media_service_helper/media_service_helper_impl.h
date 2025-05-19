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

#ifndef MEDIA_SERVICE_HELPER_IMPL_H
#define MEDIA_SERVICE_HELPER_IMPL_H

#include "media_service_helper/media_service_helper.h"
#include "nocopyable.h"
#include "osal/task/autolock.h"

namespace OHOS {
namespace Media {
class MediaServiceHelperImpl : public MediaServiceHelper, public NoCopyable {
public:
    MediaServiceHelperImpl();
    ~MediaServiceHelperImpl();

    bool CanKillMediaService() override;
};
} // namespace Media
} // namespace OHOS
#endif // PLAYER_IMPL_H

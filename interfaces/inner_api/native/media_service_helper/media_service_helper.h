/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MEDIA_SERVICE_HELPER_H
#define MEDIA_SERVICE_HELPER_H

#include <cstdint>
#include "media_core.h"
#include "meta/format.h"

namespace OHOS {
namespace Media {

class MediaServiceHelper {
public:
    virtual ~MediaServiceHelper() = default;

    /**
     * @brief Checks wheather media service can be killed or not.
     *
     * @return Returns true if media service can be killed; false otherwhise.
     * @since 1.0
     * @version 1.0
     */
    virtual bool CanKillMediaService()
    {
        return false;
    }
};

class __attribute__((visibility("default"))) MediaServiceHelperFactory {
public:
    static std::shared_ptr<MediaServiceHelper> CreateMediaServiceHelper();
private:
    MediaServiceHelperFactory() = default;
    ~MediaServiceHelperFactory() = default;
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_SERVICE_HELPER_H

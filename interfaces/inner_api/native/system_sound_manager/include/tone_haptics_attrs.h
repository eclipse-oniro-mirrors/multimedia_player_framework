/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TONE_HAPTICS_ATTRS_H
#define TONE_HAPTICS_ATTRS_H

#include <string>

namespace OHOS {
namespace Media {

enum ToneHapticsMode {
    NONE = 0,
    SYNC = 1,
    NON_SYNC = 2,
};

struct ToneHapticsSettings {
    ToneHapticsMode mode = NONE;
    std::string hapticsUri = "";
};

class ToneHapticsAttrs {
public:
    ToneHapticsAttrs(std::string title, std::string fileName, std::string uri) : title_(title),
        fileName_(fileName), uri_(uri) {}
    ~ToneHapticsAttrs() = default;
    /**
     * @brief Returns the title of the tone haptics attrs.
     *
     * @return Returns title as string if the title is obtained successfully.
     * returns an empty string otherwise.
     * @since 12
     */
    std::string GetTitle() const
    {
        return title_;
    }

    std::string GetFileName() const
    {
        return fileName_;
    }

    std::string GetUri() const
    {
        return uri_;
    }

private:
    std::string title_ = "title_test";
    std::string fileName_ = "fileName_test";
    std::string uri_ = "uri_test";
};
} // Media
} // OHOS
#endif // TONE_HAPTICS_ATTRS_H

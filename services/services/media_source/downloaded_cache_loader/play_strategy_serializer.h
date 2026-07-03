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

#ifndef PLAY_STRATEGY_SERIALIZER_H
#define PLAY_STRATEGY_SERIALIZER_H

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

namespace OHOS {
namespace Media {
namespace Plugins {
struct PlayStrategy;
struct TrackSelectionFilter;
}

namespace DownloadedCache {

class PlayStrategySerializer {
public:
    static bool Serialize(const std::string& rootUrl,
                          const Plugins::PlayStrategy& strategy,
                          const Plugins::TrackSelectionFilter& filter,
                          std::vector<uint8_t>& output);
    
    static bool Deserialize(const std::vector<uint8_t>& input,
                            std::string& rootUrl,
                            Plugins::PlayStrategy& strategy,
                            Plugins::TrackSelectionFilter& filter);
    
    static bool WriteToFile(std::ofstream& file,
                            const std::string& rootUrl,
                            const Plugins::PlayStrategy& strategy,
                            const Plugins::TrackSelectionFilter& filter);
    
    static bool ReadFromFile(std::ifstream& file,
                             std::string& rootUrl,
                             Plugins::PlayStrategy& strategy,
                             Plugins::TrackSelectionFilter& filter);

private:
    static constexpr size_t BOOL_SIZE = 1;
    static constexpr size_t INT32_SIZE = 4;
    static constexpr size_t UINT32_SIZE = 4;
    static constexpr size_t DOUBLE_SIZE = 8;
};

} // namespace DownloadedCache
} // namespace Media
} // namespace OHOS

#endif // PLAY_STRATEGY_SERIALIZER_H
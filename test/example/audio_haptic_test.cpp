/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef LOG_TAG
#define LOG_TAG "AudioHapticTest"
#endif
#include <chrono>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <thread>

#include "media_errors.h"

#include "audio_haptic_manager_impl.h"
#include "audio_haptic_test_common.h"

using namespace OHOS;
using namespace OHOS::Media;

constexpr int32_t ERROR_FILE_DESCRIPTOR = -1;
constexpr int32_t ERROR_RESULT = -1;
constexpr int32_t ERROR_EXIT = -1;
constexpr int32_t MESSGE_OK = 0;

static std::shared_ptr<AudioHapticManagerImpl> g_audioHapticManagerImpl = nullptr;

static int32_t RegisterSource(std::string audioFilePath, std::string hapticFilePath)
{  
    int32_t audioFd = open(audioFilePath.c_str(), O_RDONLY);
    struct stat64 audioBuff = { 0 };
    int32_t ret = fstat64(audioFd, &audioBuff);
    if (ret == ERROR_FILE_DESCRIPTOR) {
        std::cerr << "Audio file invalid: " << audioFilePath << std::endl;
        return ERROR_RESULT;
    }
    AudioHapticFileDescriptor audioFile;
    audioFile.fd = audioFd;
    audioFile.offset = 0;
    audioFile.length = audioBuff.st_size;

    int32_t hapticDd = open(hapticFilePath.c_str(), O_RDONLY);
    struct stat64 hatpicBuff = { 0 };
    ret = fstat64(hapticDd, &hatpicBuff);
    if (ret == ERROR_FILE_DESCRIPTOR) {
        std::cerr << "Haptic file invalid: " << hapticFilePath << std::endl;
        return ERROR_RESULT;
    }
    AudioHapticFileDescriptor hapticFile;
    hapticFile.fd = hapticDd;
    hapticFile.offset = 0;
    hapticFile.length = hatpicBuff.st_size;

    ret = g_audioHapticManagerImpl->RegisterSourceFromFd(audioFile, hapticFile);
    close(audioFd);
    close(hapticDd);

    return ret;
}

static void HandleCommand(const std::shared_ptr<AudioHapticPlayer> &player)
{
    std::string command;
    while (true) {
        std::cout << "Enter command (start/gentle/stop/exit): ";
        std::cin >> command;

        if (command == "start") {
            player->Start();
        } else if (command == "gentle") {
            player->SetHapticsFeature(HapticsFeature::GENTLE_HAPTICS);
        } else if (command == "stop") {
            player->Stop();
        } else if (command == "exit") {
            break;
        } else {
            std::cout << "Unknown command" << std::endl;
        }
    }
}

int main()
{
    uint64_t tokenID;
    GetPermission({"ohos.permission.VIBRATE"}, tokenID, true);

    g_audioHapticManagerImpl = std::make_shared<AudioHapticManagerImpl>();

    std::string audioFilename = "demo.ogg";
    std::string vibrationFilename = "demo.json";

    int32_t sourceId = RegisterSource(audioFilename, vibrationFilename);
    if (sourceId == ERROR_RESULT) {
        std::cout << "failed to register source" << std::endl;
        return ERROR_EXIT;
    }

    AudioHapticPlayerOptions options;
    std::shared_ptr<AudioHapticPlayer> player = g_audioHapticManagerImpl->CreatePlayer(sourceId, options);
    if (player == nullptr) {
        std::cout << "failed to create player" << std::endl;
        return ERROR_EXIT;
    }

    int32_t result = player->Prepare();
    if (result != MESSGE_OK) {
        std::cout << "failed to prepare player" << std::endl;
        return ERROR_EXIT;
    }

    HandleCommand(player);

    // Clean up resources
    player->Release();
    g_audioHapticManagerImpl->UnregisterSource(sourceId);

    return 0;
}
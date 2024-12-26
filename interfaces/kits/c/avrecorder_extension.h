/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVRECORDER_EXTENSION_H
#define MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVRECORDER_EXTENSION_H

#ifdef __cplusplus
extern "C" {
#endif

const float MAX_LATITUDE = 90.0f;
const float MIN_LATITUDE = -90.0f;
const float MAX_LONGITUDE = 180.0f;
const float MIN_LONGITUDE = -180.0f;

/**
Enumerates the video rotation.
*/
enum RotationAngle {
    /**
    * Video without rotation
    */
    ROTATION_0 = 0,
    /**
    * Video rotated 90 degrees
    */
    ROTATION_90 = 90,
    /**
    * Video rotated 180 degrees
    */
    ROTATION_180 = 180,
    /**
    * Video rotated 270 degrees
    */
    ROTATION_270 = 270
};


#ifdef __cplusplus
}
#endif

#endif // MULTIMEDIA_PLAYER_FRAMEWORK_NATIVE_AVRECORDER_EXTENSION_H
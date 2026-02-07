OpenHarmony
同步事件侵入式消分备案黄蓝差异黄蓝差异(CR)个人提交跟踪看板项目提交跟踪看板DTS问题单看板
Welcome, z00654174 
黄蓝差异 详情
multimedia_player_framework黄蓝差异详情
test/unittest/lpp_unit_test/module/lpp_sync_mgr_adapter_unit_test/mock/v1_0/ilow_power_player_factory.h
multimedia_player_framework
master
huawei/EMUI/HarmonyOS/hmos_trunk_dev_20260115/OpenHarmony-Trunk
待处理
--
--
test/fuzztest/lowpoweravsink_fuzztest/lowpowervideosink_fuzzer/lowpowervideosink_fuzzer.cpp
multimedia_player_framework
master
huawei/EMUI/HarmonyOS/hmos_trunk_dev_20260115/OpenHarmony-Trunk
待处理
--
--
test/fuzztest/lowpoweravsink_fuzztest/lowpowervideosink_fuzzer/BUILD.gn
multimedia_player_framework
master
huawei/EMUI/HarmonyOS/hmos_trunk_dev_20260115/OpenHarmony-Trunk
待处理
--
--
test/fuzztest/lowpoweravsink_fuzztest/lowpoweraudiosink_fuzzer/lowpoweraudiosink_fuzzer.cpp
multimedia_player_framework
master
huawei/EMUI/HarmonyOS/hmos_trunk_dev_20260115/OpenHarmony-Trunk
待处理
--
--
test/fuzztest/lowpoweravsink_fuzztest/lowpoweraudiosink_fuzzer/BUILD.gn
multimedia_player_framework
master
huawei/EMUI/HarmonyOS/hmos_trunk_dev_20260115/OpenHarmony-Trunk
待处理
--
--
interfaces/kits/c/lowpower_avsink_base.h
multimedia_player_framework
master
huawei/EMUI/HarmonyOS/hmos_trunk_dev_20260115/OpenHarmony-Trunk
待处理
--
--
共 6 条
10条/页


前往
1
页
interfaces/kits/c/lowpower_avsink_base.h-黄蓝区差异详情

蓝区代码
黄区代码
typedef struct OH_AVSamplesBuffer OH_AVSamplesBuffer;

/**
 * @brief Forward declaration of OH_LowPowerAVSink_Capability.
 *
 * @since 21
 */
typedef struct OH_LowPowerAVSink_Capability OH_LowPowerAVSink_Capability;

/**
 * @brief Append one OH_AVBuffer data to framePacketBuffer instance.
 *
 * This function queries and returns the capability set supported by the current
 * lowpower audio/video sink, including but not limited to supported media formats, etc.
 *
 * @return {OH_LowPowerAVSink_Capability*}
 *         - A pointer to the capability structure if the sink supports capability queries and the query is successful.
 *         - nullptr if the sink does not support capability queries or the query fails.
 
 * @since 21
 */
OH_LowPowerAVSink_Capability *OH_LowPowerAVSink_GetCapability();
#ifdef __cplusplus
}
typedef struct OH_AVSamplesBuffer OH_AVSamplesBuffer;

/**
 * @brief Forward declaration of OH_LowPowerAVSink_Capability.
 *
 * @since 20
 */
typedef struct OH_LowPowerAVSink_Capability OH_LowPowerAVSink_Capability;

/**
 * @brief Append one OH_AVBuffer data to framePacketBuffer instance.
 *
 * This function queries and returns the capability set supported by the current
 * lowpower audio/video sink, including but not limited to supported media formats, etc.
 *
 * @return {OH_LowPowerAVSink_Capability*}
 * - A pointer to the capability structure if the sink supports capability queries and the query is successful.
 * - nullptr if the sink does not support capability queries or the query fails.

 * @since 21
 */
OH_LowPowerAVSink_Capability *OH_LowPowerAVSink_GetCapability();
#ifdef __cplusplus
}

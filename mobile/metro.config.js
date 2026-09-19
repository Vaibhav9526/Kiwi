const { getDefaultConfig, mergeConfig } = require("@react-native/metro-config");

/**
 * Metro configuration (RN CLI template shape). No custom resolvers yet.
 */
module.exports = mergeConfig(getDefaultConfig(__dirname), {});

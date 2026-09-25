/**
 * App identity constants — T-315. The version is read at BUILD TIME from
 * the real manifests: tauri.conf.json is the version Tauri bakes into the
 * release binary; package.json is the fallback for web-only dev builds.
 * Single source — never a hardcoded string that drifts.
 */
import { version as tauriVersion } from "../src-tauri/tauri.conf.json";
import { version as pkgVersion } from "../package.json";

export const APP_VERSION: string = tauriVersion || pkgVersion;
export const APP_NAME = "KIWI";
export const APP_LICENSE = "Mozilla Public License 2.0";

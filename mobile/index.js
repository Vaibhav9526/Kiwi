import { AppRegistry } from "react-native";
import { App } from "./src/App";
// AUTH-15 / authenticator.md §7: the root registers under the documented
// authenticator name; `name` remains the RN package identifier.
import { name as appName, displayName } from "./app.json";

AppRegistry.registerComponent(displayName ?? appName, () => App);

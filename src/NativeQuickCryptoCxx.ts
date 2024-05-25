import { TurboModule, TurboModuleRegistry } from "react-native";

export interface Spec extends TurboModule {
  install(): number;
}

export default TurboModuleRegistry.get<Spec>("RTNQuickCryptoCxx") as Spec | null;

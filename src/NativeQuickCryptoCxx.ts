import { TurboModule, TurboModuleRegistry } from "react-native";

export interface Spec extends TurboModule {
  install(a: number, b: number): number;
}

export default TurboModuleRegistry.get<Spec>("RTNQuickCryptoCxx") as Spec | null;

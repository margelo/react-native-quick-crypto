import React, { useState } from 'react';
import { ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import BouncyCheckbox from 'react-native-bouncy-checkbox';
import { CorrectResultItem } from '../../components/CorrectResultItem';
import { IncorrectResultItem } from '../../components/IncorrectResultItem';
import { Suite } from '../../components/Suite';
import type { RouteParams } from '../../types/Results';
import { colors } from '../../styles/colors';

interface DetailsScreenProps {
  titlePrefix: string;
  route: { params: RouteParams };
}

export const DetailsScreen: React.FC<DetailsScreenProps> = ({
  titlePrefix,
  route,
}) => {
  const { results, suiteName }: RouteParams = route.params;
  const [showFailed, setShowFailed] = useState<boolean>(true);
  const [showPassed, setShowPassed] = useState<boolean>(true);

  return (
    <SafeAreaView style={styles.container} edges={['left', 'right']}>
      <View>
        <Text style={styles.title}>
          {titlePrefix} Results for '{suiteName}' Suite
        </Text>
      </View>
      <View style={styles.showMenu}>
        <View style={styles.showMenuItem}>
          <BouncyCheckbox
            isChecked={showFailed}
            onPress={() => setShowFailed(!showFailed)}
            fillColor="red"
            style={styles.checkbox}
            testID="show-failed-checkbox"
            disableBuiltInState={true}
          />
          <Text style={styles.showMenuLabel}>Show Failed</Text>
        </View>
        <View style={styles.showMenuItem}>
          <BouncyCheckbox
            isChecked={showPassed}
            onPress={() => setShowPassed(!showPassed)}
            fillColor={colors.green}
            style={styles.checkbox}
            testID="show-passed-checkbox"
            disableBuiltInState={true}
          />
          <Text style={styles.showMenuLabel}>Show Passed</Text>
        </View>
      </View>
      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.scrollContent}
      >
        {results.map((it, index: number) => {
          let InnerElement = <View key={index} />;
          if (showPassed && it.type === 'correct') {
            InnerElement = (
              <CorrectResultItem key={index} description={it.description} />
            );
          }
          if (showFailed && it.type === 'incorrect') {
            const errorMsg = it.errorMsg || '';
            InnerElement = (
              <IncorrectResultItem
                key={index}
                description={it.description}
                errorMsg={errorMsg}
              />
            );
          }
          if (it.type === 'grouping') {
            InnerElement = <Suite key={index} description={it.description} />;
          }
          return InnerElement;
        })}
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    paddingBottom: 30,
  },
  title: {
    textAlign: 'center',
    paddingVertical: 5,
  },
  showMenu: {
    flexDirection: 'row',
    width: '100%',
    justifyContent: 'space-evenly',
    paddingBottom: 5,
  },
  showMenuItem: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  showMenuLabel: {
    paddingLeft: 5,
  },
  scroll: {
    width: '100%',
  },
  scrollContent: {
    paddingHorizontal: 5,
  },
  checkbox: {
    transform: [{ scaleX: 0.8 }, { scaleY: 0.8 }],
  },
});

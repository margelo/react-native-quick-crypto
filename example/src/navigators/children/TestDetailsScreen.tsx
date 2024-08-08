import React, {useState} from 'react';
import type {NativeStackScreenProps} from '@react-navigation/native-stack';
import {SafeAreaView, ScrollView, StyleSheet, Text, View} from 'react-native';
import BouncyCheckbox from 'react-native-bouncy-checkbox';
import {CorrectResultItem} from '../../components/CorrectResultItem';
import {IncorrectResultItem} from '../../components/IncorrectResultItem';
import {Suite} from '../../components/Suite';
import {TestResult} from '../../types/Results';

type TestDetailsScreenProps = {
  route: any;
};

type RouteParams = {
  results: TestResult[];
  suiteName: string;
};

export const TestDetailsScreen = ({route}: TestDetailsScreenProps) => {
  const {results, suiteName}: RouteParams = route.params;
  const [showFailed, setShowFailed] = useState<boolean>(true);
  const [showPassed, setShowPassed] = useState<boolean>(true);

  return (
    <SafeAreaView style={styles.container}>
      <View>
        <Text style={styles.title}>Test Results for '{suiteName}' Suite</Text>
      </View>
      <View style={styles.showMenu}>
        <View style={styles.showMenuItem}>
          <BouncyCheckbox
            isChecked={showFailed}
            onPress={() => setShowFailed(!showFailed)}
            disableText={true}
            fillColor="red"
          />
          <Text style={styles.showMenuLabel}>Show Failed</Text>
        </View>
        <View style={styles.showMenuItem}>
          <BouncyCheckbox
            isChecked={showPassed}
            onPress={() => setShowPassed(!showPassed)}
            disableText={true}
            fillColor="green"
          />
          <Text style={styles.showMenuLabel}>Show Passed</Text>
        </View>
      </View>
      <ScrollView
        style={styles.scroll}
        contentContainerStyle={styles.scrollContent}>
        {results.map((it, index: number) => {
          let InnerElement = <View key={index} />;
          if (showPassed && it.type === 'correct') {
            InnerElement = (
              <CorrectResultItem key={index} description={it.description} />
            );
          }
          if (showFailed && it.type === 'incorrect') {
            const errorMsg = it.errorMsg || ''; // Trick TS - How to do it as it should be? :)
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
});

import React from 'react'
import { View, Text, StyleSheet, TouchableOpacity } from 'react-native'
import BouncyCheckbox from 'react-native-bouncy-checkbox'
import type { BenchmarkResult } from '../types/Results'
import { useNavigation } from '@react-navigation/native'
import { calculateTimes, formatNumber } from '../benchmarks/utils'
import { colors } from '../styles/colors'

type BenchmarkItemProps = {
  description: string
  value: boolean
  count: number
  results: BenchmarkResult[]
  onToggle: (description: string) => void
}

export const BenchmarkItem: React.FC<BenchmarkItemProps> = ({
  description,
  value,
  count,
  results,
  onToggle,
}: BenchmarkItemProps) => {
  const navigation = useNavigation()
  const stats = {
    us: 0,
    them: 0,
  }
  results.map((r) => {
    stats.us += r.us
    stats.them += r.them
  })
  const timesType = stats.us < stats.them ? 'faster' : 'slower'
  const timesStyle = timesType === 'faster' ? styles.faster : styles.slower
  const times = calculateTimes({
    type: timesType,
    ...stats,
    // rest of these are for matching type, ignore
    description: '',
    indentation: 0,
    suiteName: '',
  })

  return (
    <View style={styles.container}>
      <BouncyCheckbox
        isChecked={value}
        onPress={() => {
          onToggle(description)
        }}
        disableText={true}
        fillColor={colors.blue}
        style={styles.checkbox}
      />
      <TouchableOpacity
        style={styles.touchable}
        onPress={() => {
          // @ts-expect-error - not dealing with navigation types rn
          navigation.navigate('BenchmarkDetailsScreen', {
            results,
            suiteName: description,
          })
        }}
      >
        <Text style={styles.label} numberOfLines={1}>
          {description}
        </Text>
        <Text style={[styles.times, timesStyle]} numberOfLines={1}>
          {formatNumber(times, 2, 'x')}
        </Text>
        <Text style={styles.count} numberOfLines={1}>
          {count}
        </Text>
      </TouchableOpacity>
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    width: '100%',
    flexDirection: 'row',
    alignContent: 'center',
    alignItems: 'center',
    justifyContent: 'space-evenly',
    gap: 10,
    borderBottomWidth: 1,
    borderBottomColor: colors.gray,
    paddingHorizontal: 10,
  },
  checkbox: {
    transform: [{ scaleX: 0.7 }, { scaleY: 0.7 }],
  },
  label: {
    fontSize: 12,
    flex: 8,
  },
  touchable: {
    flex: 1,
    flexDirection: 'row',
  },
  faster: {
    color: colors.green,
  },
  slower: {
    color: colors.red,
  },
  times: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'right',
  },
  count: {
    fontSize: 12,
    fontWeight: 'bold',
    flex: 1,
    textAlign: 'right',
  },
})

import rnqc from 'react-native-quick-crypto'
import { RandomBytesFn } from '../types'

const randomBytes10: RandomBytesFn = () => {
  rnqc.randomBytes(10)
}

const randomBytes1024: RandomBytesFn = () => {
  rnqc.randomBytes(1024)
}

export default {
  randomBytes10,
  randomBytes1024,
}

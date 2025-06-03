const { createRNQCPlugin } = require('./lib/commonjs/expo-plugin/withRNQC');
const pkg = require('./package.json');
module.exports = createRNQCPlugin(pkg.name, pkg.version);

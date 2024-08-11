module.exports = {
  root: true,
  extends: [
    "@react-native",
    "prettier"
  ],
  rules: {
    "prettier/prettier": [
      "warn",
      {
        "object-curly-spacing": ["always"],
        quoteProps: "consistent",
        singleQuote: true,
        tabWidth: 2,
        trailingComma: "es5",
        useTabs: false,
        semi: true,
      }
    ]
  },
  ignorePatterns: [
    "node_modules/",
    "lib/"
  ]
};

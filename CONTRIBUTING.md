# Contributing

We want this community to be friendly and respectful to each other. Please follow it in all your interactions with the project.

## Development workflow

To get started with the project, run `bun install` in the root directory to install the required dependencies for each package:

```sh
bun i
```

> While it's possible to use [`npm`](https://github.com/npm/cli), [`yarn`](https://classic.yarnpkg.com/), or [`pnpm`](https://pnpm.io), the tooling is built around [`bun`](https://bun.sh), so you'll have an easier time if you use `bun` for development.

If you are using a VSCode-flavored IDE and the `clangd` extension, you can use the `scripts/setup_clang_env.sh` script to set up the environment for C++ development. This will create a `compile_commands.json` file in the root directory of the project, which will allow the IDE to provide proper includes, better code completion and navigation.  After that, add the following to your `.vscode/settings.json` file:

```json
{
    "clangd.arguments": [
        "-log=verbose", 
        "-pretty", 
        "--background-index", 
        "--compile-commands-dir=${workspaceFolder}/packages/react-native-quick-crypto/"
    ],
}
```

While developing, you can run the [example app](/example/) to test your changes. Any changes you make in your library's JavaScript code will be reflected in the example app without a rebuild. If you change any native code, then you'll need to rebuild the example app.

To develop in iOS, build the CocoaPods dependencies:

```sh
pod install
```

To start the Metro bundler/packager:

```sh
bun start
```


To start the app:
```sh
bun ios # or android
```

Make sure your code passes TypeScript and ESLint. Run the following to verify:

```sh
bun tsc
bun lint
bun format
```

To fix formatting errors, run the following:

```sh
bun lint:fix
bun format:fix
```

Remember to add tests for your change if possible. Run the unit tests by:

```sh
bun test
```

To edit the Objective-C files, open `example/ios/QuickCryptoExample.xcworkspace` in XCode and find the source files at `Pods > Development Pods > react-native-quick-crypto`.

To edit the Kotlin files, open `example/android` in Android studio and find the source files at `margelo/quickcrypto` under `Android`.

### Commit message convention

We follow the [conventional commits specification](https://www.conventionalcommits.org/en) for our commit messages:

- `fix`: bug fixes, e.g. fix crash due to deprecated method.
- `feat`: new features, e.g. add new method to the module.
- `refactor`: code refactor, e.g. migrate from class components to hooks.
- `docs`: changes into documentation, e.g. add usage example for the module..
- `test`: adding or updating tests, e.g. add integration tests using detox.
- `chore`: tooling changes, e.g. change CI config.

### Linting and tests

[ESLint](https://eslint.org/), [Prettier](https://prettier.io/), [TypeScript](https://www.typescriptlang.org/)

We use [TypeScript](https://www.typescriptlang.org/) for type checking, [ESLint](https://eslint.org/) with [Prettier](https://prettier.io/) for linting and formatting the code, and [Jest](https://jestjs.io/) for testing.

Our CI verify that the linter and tests pass when creating a PR.

### Publishing to npm

We use [release-it](https://github.com/release-it/release-it) to make it easier to publish new versions. It handles common tasks like bumping version based on semver, creating tags and releases etc.

Releases are published via GitHub Actions using npm's OIDC trusted publishing (no tokens required). To publish a new version:

1. Go to **Actions** → **Release** → **Run workflow**
2. Select the `main` branch
3. Enter the version (e.g., `1.0.0-beta.21`) or increment type (`patch`, `minor`, `major`, `prerelease`)
4. Optionally check "Dry run" to test without publishing
5. Click **Run workflow**

The workflow will:
- Bump the version in package.json
- Build and publish to npm with provenance attestation
- Create a git tag and GitHub release

### Scripts

The `package.json` file contains various scripts for common tasks:

- `bun bootstrap`: setup project by installing all dependencies and pods.
- `bun tsc`: type-check files with TypeScript.
- `bun lint`: lint files with ESLint.
- `bun test`: run unit tests with Jest.
- `bun example`: start the Metro server for the example app.

### Sending a pull request

> **Working on your first pull request?** You can learn how from this _free_ series: [How to Contribute to an Open Source Project on GitHub](https://app.egghead.io/playlists/how-to-contribute-to-an-open-source-project-on-github).

When you're sending a pull request:

- Prefer small pull requests focused on one change.
- Verify that linters and tests are passing.
- Review the documentation to make sure it looks good.
- Follow the pull request template when opening a pull request.
- For pull requests that change the API or implementation, discuss with maintainers first by opening an issue.

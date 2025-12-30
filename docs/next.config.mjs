import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX();

const isGitHubPages = process.env.GITHUB_ACTIONS === 'true';

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  output: 'export',
  basePath: isGitHubPages ? '/react-native-quick-crypto' : '',
  assetPrefix: isGitHubPages ? '/react-native-quick-crypto/' : '',
};

export default withMDX(config);

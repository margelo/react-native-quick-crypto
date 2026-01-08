import { build } from 'esbuild';
import path from 'path';

const measure = async (name: string, entryPoint: string) => {
    const result = await build({
        entryPoints: [entryPoint],
        bundle: true,
        minify: true,
        format: 'esm',
        platform: 'browser',
        external: ['react-native-quick-crypto', 'react-native'],
        write: false,
        outfile: 'bundle.js'
    });

    const text = result.outputFiles[0].text;
    const bytes = Buffer.byteLength(text);
    const kb = (bytes / 1024).toFixed(2);

    console.log(`📦 ${name}: ${kb} KB (${bytes} bytes)`);
};

const run = async () => {
    console.log('\n--- Bundle Size Report ---\n');
    await measure('Minimal (English only)', path.join(__dirname, '../src/index.ts'));
    await measure('Maximal (All Languages)', path.join(__dirname, '../src/bench-all.ts'));
    console.log('\n(Minified, excluding peer dependencies)\n');
};

run();

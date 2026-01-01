import { writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';

const SOURCES = {
    spanish: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/spanish.txt',
    french: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/french.txt',
    italian: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/italian.txt',
    japanese: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/japanese.txt',
    korean: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/korean.txt',
    chinese_simplified: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/chinese_simplified.txt',
    chinese_traditional: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/chinese_traditional.txt',
    czech: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/czech.txt',
    portuguese: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/portuguese.txt',
    english: 'https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt',
};

const OUT_DIR = join(__dirname, '../src/wordlists');
mkdirSync(OUT_DIR, { recursive: true });

async function fetchAndWrite() {
    const exports: string[] = [];

    for (const [lang, url] of Object.entries(SOURCES)) {
        console.log(`Fetching ${lang} from ${url}...`);
        try {
            const response = await fetch(url);
            const text = await response.text();
            const words = text.split('\n').map(w => w.trim()).filter(w => w.length > 0);

            if (words.length !== 2048) {
                console.warn(`⚠️ Warning: ${lang} wordlist has ${words.length} words (expected 2048)`);
            }

            const fileContent = `// BIP39 ${lang} wordlist
// Source: ${url}
export const wordlist = ${JSON.stringify(words, null, 2)} as const;
`;

            writeFileSync(join(OUT_DIR, `${lang}.ts`), fileContent);
            console.log(`✅ Wrote ${lang}.ts`);
            exports.push(lang);
        } catch (e) {
            console.error(`❌ Failed to fetch ${lang}:`, e);
        }
    }

    const indexContent = exports.map(lang => `import { wordlist as ${lang} } from './${lang}';`).join('\n') +
        `\n\nexport const wordlists = {\n` +
        exports.map(lang => `  ${lang},`).join('\n') +
        `\n};\n`;

    writeFileSync(join(OUT_DIR, 'index.ts'), indexContent);
    console.log(`✅ Wrote index.ts`);
}

fetchAndWrite();

import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import alias from '@rollup/plugin-alias';
import dts from 'rollup-plugin-dts';
import esbuild from 'rollup-plugin-esbuild';

const pkg = createRequire(import.meta.url)('./package.json');

const makeExternalPredicate = (externalArr) => {
  if (externalArr.length === 0) {
    return () => false;
  }
  const pattern = new RegExp(`^(${externalArr.join('|')})($|/)`);
  return (id) => pattern.test(id);
};

const outputOptions = {
  exports: 'named',
  banner: `/*
 * Laravel Encrypter for JavaScript.
 * {@link https://github.com/rugaard/laravel-encrypter}
 * @copyright Morten Rugaard (@rugaard)
 * @license MIT
 */`,
};

export default [
  {
    input: 'src/index.ts',
    output: [
      {
        file: 'dist/index.esm.js',
        format: 'esm',
        ...outputOptions
      },
      {
        file: 'dist/index.cjs.js',
        format: 'cjs',
        ...outputOptions
      },
    ],
    external: makeExternalPredicate([
      ...Object.keys(pkg.dependencies || {}),
      ...Object.keys(pkg.peerDependencies || {}),
    ]),
    plugins: [
      alias({
        entries: {
          src: fileURLToPath(new URL('src', import.meta.url)),
        },
      }),
      esbuild({ minify: true }),
    ],
  },
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/index.d.ts',
      format: 'esm',
      ...outputOptions
    },
    plugins: [
      alias({
        entries: {
          src: fileURLToPath(new URL('src', import.meta.url)),
        },
      }),
      dts()
    ],
  },
];

import resolve from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';
import terser from '@rollup/plugin-terser';

export default [
  // ESM build
  {
    input: 'js/index.ts',
    output: {
      file: 'dist/shield-browser.esm.js',
      format: 'esm',
      sourcemap: true,
    },
    plugins: [
      resolve(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
      }),
    ],
    external: ['../pkg/shield_browser.js'],
  },
  // UMD build
  {
    input: 'js/index.ts',
    output: {
      file: 'dist/shield-browser.js',
      format: 'umd',
      name: 'ShieldBrowser',
      sourcemap: true,
      globals: {
        '../pkg/shield_browser.js': 'ShieldWasm',
      },
    },
    plugins: [
      resolve(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
      }),
    ],
    external: ['../pkg/shield_browser.js'],
  },
  // Minified UMD build
  {
    input: 'js/index.ts',
    output: {
      file: 'dist/shield-browser.min.js',
      format: 'umd',
      name: 'ShieldBrowser',
      globals: {
        '../pkg/shield_browser.js': 'ShieldWasm',
      },
    },
    plugins: [
      resolve(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false,
      }),
      terser(),
    ],
    external: ['../pkg/shield_browser.js'],
  },
];

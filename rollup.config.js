import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import fs from "fs";
import { terser } from "rollup-plugin-terser";
import typescript from "@rollup/plugin-typescript";
import emitModulePackageFile from "./build-plugins/emit-module-package-file.js";
//import replaceBrowserModules from './build-plugins/replace-browser-modules.js';
import pkg from "./package.json";
//import serve from 'rollup-plugin-serve';
//import nodePolyfills from 'rollup-plugin-node-polyfills';
//import nodePolyfills from 'rollup-plugin-polyfill-node'; // Latest maintained version with fixes for the FS polyfills and others, from snowpackjs team.
import replace from "@rollup/plugin-replace";
import globals from "rollup-plugin-node-globals";
import alias from "@rollup/plugin-alias";
import inject from "@rollup/plugin-inject";
import size from "rollup-plugin-size";
import { visualizer } from "rollup-plugin-visualizer";
// import replaceFiles from 'rollup-plugin-file-content-replace';
import eslint from "@rollup/plugin-eslint";
import sourcemaps from "rollup-plugin-sourcemaps";

import { writeFileSync } from "fs";

// Very dirty way to get rid on unsupported languages BIP39 languages to reduce the bundle size.
// rollup-plugin-file-content-replace wasn't able to stub language json files and found no better way
// than this hack currently.
// NOTE: as the node_modules/bip39 folder is modified, re-adding a languages requires reinstalling
// the bip39 library.
writeFileSync(
  __dirname + "/node_modules/bip39/src/wordlists/chinese_traditional.json",
  "[]"
);
writeFileSync(__dirname + "/node_modules/bip39/src/wordlists/czech.json", "[]");
writeFileSync(
  __dirname + "/node_modules/bip39/src/wordlists/italian.json",
  "[]"
);
writeFileSync(
  __dirname + "/node_modules/bip39/src/wordlists/japanese.json",
  "[]"
);
writeFileSync(
  __dirname + "/node_modules/bip39/src/wordlists/korean.json",
  "[]"
);
writeFileSync(
  __dirname + "/node_modules/bip39/src/wordlists/portuguese.json",
  "[]"
);
writeFileSync(
  __dirname + "/node_modules/bip39/src/wordlists/spanish.json",
  "[]"
);

const commitHash = (function () {
  try {
    return fs.readFileSync(".commithash", "utf-8");
  } catch (err) {
    return "unknown";
  }
})();

process.env.prodbuild = false; //TMP

const prodBuild = process.env.prodbuild || false;
console.log("Prod build: ", prodBuild);

const now = new Date(
  process.env.SOURCE_DATE_EPOCH
    ? process.env.SOURCE_DATE_EPOCH * 1000
    : new Date().getTime()
).toUTCString();

const banner = `/*
  @license
    Wallet.js v${pkg.version}
    ${now} - commit ${commitHash}

    Released under the MIT License.
*/`;

const onwarn = (warning) => {
  // eslint-disable-next-line no-console
  if (
    warning.code &&
    warning.code === "CIRCULAR_DEPENDENCY" &&
    warning.importer.indexOf("node_modules") < 0 &&
    warning.importer.indexOf("internals.ts") >= 0
  )
    return; // TMP: don't get flooded by our "internals" circular dependencies for now

  // eslint-disable-next-line no-console
  if (
    warning.code &&
    warning.code === "CIRCULAR_DEPENDENCY" &&
    (warning.importer.indexOf("node_modules") > -1 ||
      warning.importer.indexOf("internals.ts") > -1 ||
      warning.importer.indexOf("src/browser/readable-stream") > -1)
  )
    return; // TMP: don't get flooded by our "internals" circular dependencies for now

  if (warning.code && warning.code === "THIS_IS_UNDEFINED") return; // TMP: don't get flooded by this for now

  if (warning.code && warning.code === "EVAL") return; // TMP: don't get flooded by this for now

  if (
    prodBuild &&
    warning.code &&
    warning.code === "PLUGIN_WARNING" &&
    warning.plugin &&
    warning.plugin === "typescript" /* &&
    warning.message.indexOf("Rollup 'sourcemap' option") > -1 */
  )
    return;

  console.warn("Rollup build warning:", warning);
};

const treeshake = {
  moduleSideEffects: false,
  propertyReadSideEffects: false,
  tryCatchDeoptimization: false
};

const nodePlugins = [
  resolve({
    preferBuiltins: true
  }),
  json({}),
  replace({
    delimiters: ["", ""],
    preventAssignment: true,
    exclude: [
      "/node_modules/rollup-plugin-node-polyfills/**/*.js",
      "/node_modules/rollup-plugin-polyfill-node/**/*.js"
    ],
    values: {
      // Replace readable-stream with stream (polyfilled) because it uses dynamic requires and this doesn't work well at runtime
      // even if trying to add "readable-stream" to "dynamicRequireTargets" in commonJs().
      // https://github.com/rollup/rollup/issues/1507#issuecomment-340550539
      "require('readable-stream')": "require('stream')",
      'require("readable-stream")': 'require("stream")',
      "require('readable-stream/writable')": "require('stream').Writable",
      'require("readable-stream/writable")': 'require("stream").Writable',
      "require('readable-stream/readable')": "require('stream').Readable",
      'require("readable-stream/readable")': 'require("stream").Readable',
      "LegacyTransportStream = require('./legacy')":
        "LegacyTransportStream = null",
      "LegacyTransportStream = require('winston-transport/legacy')":
        "LegacyTransportStream = null"
    }
  }),
  typescript({
    //include: ["index.ts", "src/walletcore/*.ts", "src/**/*.ts"],
    exclude: "*.browser.ts"
  }),
  commonjs({}),
  size()
];

export default (command) => {
  //const { collectLicenses, writeLicense } = getLicenseHandler();
  const nodeBuild = {
    input: {
      "wallet.js": "src/index.ts"
    },
    onwarn,
    plugins: [
      ...nodePlugins,
      //!command.configTest && collectLicenses()
      eslint()
    ],
    // fsevents is a dependency of chokidar that cannot be bundled as it contains binary code
    external: [
      "assert",
      "axios",
      "crypto",
      "events",
      "fs",
      "fsevents",
      "module",
      "path",
      "os",
      "stream",
      "url",
      "util"
    ],
    treeshake,
    strictDeprecations: true,
    output: {
      banner,
      chunkFileNames: "shared/[name].js",
      dir: "dist",
      entryFileNames: "[name]",
      externalLiveBindings: false,
      format: "cjs",
      freeze: false,
      // TODO: delete occurences of fsevents - not used in wallet sdk
      interop: (id) => {
        if (id === "fsevents") {
          return "defaultOnly";
        }
        return "default";
      },
      manualChunks: { wallet: ["src/index.ts"] },
      sourcemap: !prodBuild
    }
  };

  if (command.configTest) {
    return nodeBuild;
  }

  const nodeEsmBuild = {
    ...nodeBuild,
    input: { "wallet.js": "src/index.ts" },
    plugins: [
      ...nodePlugins,
      emitModulePackageFile()
      //collectLicenses()
    ],
    output: {
      ...nodeBuild.output,
      dir: "dist/es",
      format: "es",
      sourcemap: !prodBuild,
      minifyInternalExports: false
    }
  };

  const browserEsmBuild = {
    input: "src/index.ts",
    onwarn,
    external: [
      "@ethersproject/abstract-provider",
      "@ethersproject/transactions",
      "bignumber.js",
      "bip32",
      "bip39",
      "bn.js",
      "elliptic",
      "bs58",
      "bs58check",
      "create-hash",
      "crypto-browserify",
      "crypto-js",
      "dayjs",
      "ethers",
      "events",
      "js-sha3",
      "random-int",
      "string_decoder"
      //'browserfs'
      /* 'readable-stream',
            'readable-stream/transform' */
    ],
    plugins: [
      // IMPORTANT: DON'T CHANGE THE ORDER OF THINGS BELOW TOO MUCH! OTHERWISE YOU'LL GET
      // GOOD HEADACHES WITH RESOLVE ERROR, UNEXPORTED CLASSES AND SO ON...
      json(),
      //collectLicenses(),
      //writeLicense(),
      // Replace some node files with their browser-specific versions.
      // Ex: fs.browser.ts -> fs.ts
      /* replaceFiles({
         fileReplacements: [
           { replace: "http.ts", with: "http.browser.ts" },
           { replace: "https.ts", with: "https.browser.ts" }
         ]
       }), */
      // Dirty circular dependency removal atttempt
      replace({
        delimiters: ["", ""],
        preventAssignment: true,
        include: ["node_modules/assert/build/internal/errors.js"],
        values: {
          "require('../assert')": "null"
        }
      }),
      // Dirty hack to remove circular deps between brorand and crypto-browserify as in browser,
      // brorand doesn't use 'crypto' even if its source code includes it.
      replace({
        delimiters: ["", ""],
        preventAssignment: true,
        include: ["node_modules/brorand/**/*.js"],
        values: {
          "require('crypto')": "null"
        }
      }),
      // Circular dependencies tips: https://github.com/rollup/rollup/issues/3816
      replace({
        delimiters: ["", ""],
        preventAssignment: true,
        values: {
          // Replace readable-stream with stream (polyfilled) because it uses dynamic requires and this doesn't work well at runtime
          // even if trying to add "readable-stream" to "dynamicRequireTargets" in commonJs().
          // https://github.com/rollup/rollup/issues/1507#issuecomment-340550539
          "require('readable-stream')": "require('stream')",
          'require("readable-stream")': 'require("stream")',
          "require('readable-stream/writable')": "require('stream').Writable",
          'require("readable-stream/writable")': 'require("stream").Writable',
          "require('readable-stream/readable')": "require('stream').Readable",
          'require("readable-stream/readable")': 'require("stream").Readable',
          "LegacyTransportStream = require('./legacy')":
            "LegacyTransportStream = null",
          "LegacyTransportStream = require('winston-transport/legacy')":
            "LegacyTransportStream = null"
        }
      }),
      alias({
        entries: [
          { find: "buffer", replacement: "buffer" },
          { find: "process", replacement: "process-es6" },
          //{ "find": "fs", "replacement": "browserfs/dist/shims/fs" },
          { find: "path", replacement: "path-browserify" },
          { find: "crypto", replacement: "crypto-browserify" },
          { find: "util/", replacement: "node_modules/util/util.js" },
          { find: "util", replacement: "node_modules/util/util.js" },
          { find: "stream", replacement: "./src/browser/stream.js" },
          {
            find: "string_decoder/",
            replacement: "node_modules/string_decoder/lib/string_decoder.js"
          },
          {
            find: "string_decoder",
            replacement: "node_modules/string_decoder/lib/string_decoder.js"
          },
          { find: "events", replacement: "node_modules/events/events.js" },
          { find: "assert", replacement: "node_modules/assert/build/assert.js" }
        ]
      }),
      resolve({
        mainFields: ["browser", "module", "jsnext:main", "main"],
        browser: true,
        preferBuiltins: false,
        dedupe: [
          "bn.js",
          "elliptic",
          "browserfs",
          "buffer",
          "buffer-es6",
          "process-es6",
          "crypto-browserify",
          "assert",
          "events",
          "browserify-sign"
        ]
      }),
      // Polyfills needed to replace readable-stream with stream (circular dep)
      commonjs({
        esmExternals: true,
        //requireReturnsDefault: "true", // "true" will generate build error: TypeError: Cannot read property 'deoptimizePath' of undefined
        //requireReturnsDefault: "auto", // namespace, true, false, auto, preferred
        transformMixedEsModules: true, // TMP trying to solve commonjs "circular dependency" errors at runtime
        dynamicRequireTargets: []
      }),
      globals({}), // Defines process, Buffer, etc
      typescript({
        exclude: "*.node.ts",
        //useTsconfigDeclarationDir: true
        sourceMap: true,
        inlineSourceMap: false
      }),
      sourcemaps(),
      /* nodePolyfills({
                stream: true
                // crypto:true // Broken, the polyfill just doesn't work. We have to use crypto-browserify directly in our TS code instead.
            }), */ // To let some modules bundle NodeJS stream, util, fs ... in browser
      inject({
        BrowserFS: "browserfs"
      }),
      // size(),
      ...(prodBuild ? [terser()] : []),
      visualizer({
        filename: "./browser-bundle-stats.html"
      }) // To visualize bundle dependencies sizes on a UI.
      // LATER terser({ module: true, output: { comments: 'some' } })
    ],
    treeshake,
    strictDeprecations: true,
    output: [
      //{ file: 'dist/wallet.browser.js', format: 'umd', name: 'wallet.js', banner, sourcemap: true },
      {
        file: "dist/es/wallet.browser.js",
        format: "es",
        banner,
        sourcemap: !prodBuild
        //intro: 'var process: { env: {}};'
        //intro: 'var global = typeof self !== undefined ? self : this;' // Fix "global is not defined"
      }
    ]
  };

  return [nodeBuild, nodeEsmBuild, browserEsmBuild];
};

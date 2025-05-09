# Wallet JS SDK

## Origin

This Typescript SDK is originated from the Elastos C++ SPVSDK. That C++ SDK is an SPV SDK and as such, can synchronize blocks and manage many things.

This JS SDK diverges a little bit from that original SDK in a few ways:

- No SPV support. Only account/wallet, transactions, signature management, but transactions are retrieved and published by RPC APIs.
- A wallet store layer is added, in order to let apps provide their own storage solution for wallet data.
- Non-elastos chains (eg BTC, Ripple) are not going to be supported. Elastos Wallet SDK must focus on the elastos chains only, and not try to support too many chains. Each chain needs to use its own SDK.

## Note

- The current version is based on that [04bee6d](https://github.com/elastos/Elastos.ELA.SPV.Cpp/tree/dev) commit ID.
- For now we continue to migrate C++ -> TS on this version

## SDK development workflow

- From the SDK folder: `npm run dev` (this enables hot reload when SDK files change)
- Or `npm run build` without hot reload.

## App integration - known issues

### "$n" is not a constructor

This issue is related to a bundler (rollup, webpack) conflict in elliptic/bn.js libraries. For some reasons, sometimes the imported "BN" class is a constructor, sometimes it's just an object that contains a BN constructor inside (mess with exported "default" symbols in libraries).

**Solution:**

On the application side, in tsconfig.json, add:

```
compilerOptions: {
  paths: {
    "elliptic": [
      "./node_modules/elliptic"
    ],
    "bn.js": [
      "./node_modules/bn.js"
    ]
  }
}
```

### run on a create-react-app with webpack 5

```
Module not found: Error: Can't resolve 'stream'
BREAKING CHANGE: webpack < 5 used to include polyfills for node.js core modules by default.
This is no longer the case. Verify if you need this module and configure a polyfill for it.
```

solution: https://alchemy.com/blog/how-to-polyfill-node-core-modules-in-webpack-5

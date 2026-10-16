# ts-scep, vendored

[ts-scep](https://github.com/northlanddynamics/ts-scep) at commit `b56eb8aa73aa419301eaac914938e9ce896c3151`, built with
`tsc -p tsconfig.build.json` (its own config) and committed as compiled JavaScript and type declarations, because it is
not published to npm. The root `package.json` depends on it as `file:./vendor/ts-scep`; its own dependencies come from npm.

Nothing here is edited by hand (source map comments aside, which pointed at sources not included). To update it, build
another commit the same way and replace `dist/`. Once ts-scep is on npm, depend on it there and delete this directory.

const {getDefaultConfig} = require('metro-config');

module.exports = (async () => {
  const {
    resolver: {sourceExts, assetExts},
  } = await getDefaultConfig();

  const defaultSourceExts = [...sourceExts, 'svg', 'mjs', 'cjs'];

  return {
    resolver: {
      extraNodeModules: {
        assert: require.resolve('empty-module'), // assert can be polyfilled here if needed
        http: require.resolve('empty-module'), // stream-http can be polyfilled here if needed
        https: require.resolve('empty-module'), // https-browserify can be polyfilled here if needed
        os: require.resolve('empty-module'), // os-browserify can be polyfilled here if needed
        url: require.resolve('empty-module'), // url can be polyfilled here if needed
        zlib: require.resolve('empty-module'), // browserify-zlib can be polyfilled here if needed
        process: require.resolve('empty-module'),
        crypto: require.resolve('empty-module'),
        stream: require.resolve('stream-browserify'),
      },

      assetExts: assetExts.filter(ext => ext !== 'svg'),

      sourceExts: process.env.TEST_REACT_NATIVE
        ? ['e2e.js'].concat(defaultSourceExts)
        : defaultSourceExts,
    },
    transformer: {
      getTransformOptions: async () => ({
        transform: {
          experimentalImportSupport: false,
          inlineRequires: true,
        },
      }),
    },
  };
})();

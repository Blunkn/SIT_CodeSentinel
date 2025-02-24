const path = require('path');

module.exports = {
  // Define the entry point for your application
  entry: {
    main: ['./script.js', './logscanner.js'], // Include both files
  },

  // Output the bundled file to the 'dist' directory
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'), // Output folder for bundled code
  },

  resolve: {
    alias: {
      acorn: path.resolve(__dirname, 'node_modules/acorn/dist/acorn.js')
    }
  },

  // Enable source maps for easier debugging
  devtool: 'source-map',

  // Resolve polyfills for Node.js modules (needed for browser compatibility)
  resolve: {
    fallback: {
      fs: require.resolve('browserify-fs'),
      path: require.resolve('path-browserify'),
      os: require.resolve('os-browserify/browser'),
      stream: require.resolve('stream-browserify'),
    },
  },

  // Set mode to development for debugging or production for optimization
  mode: 'development', // Change to 'production' when you're ready to deploy

  // For development server (optional but useful)
  devServer: {
    contentBase: path.join(__dirname, 'dist'),
    compress: true,
    port: 9000,
  },
};
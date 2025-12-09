module.exports = {
  dependency: {
    platforms: {
      ios: {
        scriptPhases: [
          {
            name: '[CP-User] Embed OpenSSL Framework',
            path: './scripts/embed_openssl_framework.sh',
            execution_position: 'after_compile',
            input_files: ['${BUILT_PRODUCTS_DIR}/OpenSSL.framework'],
            output_files: [
              '${TARGET_BUILD_DIR}/${FRAMEWORKS_FOLDER_PATH}/OpenSSL.framework',
            ],
          },
        ],
      },
    },
  },
};

import { configWithoutCloudSupport } from '@n8n/node-cli/eslint';

// This node uses a raw TCP socket (the meshcore.js `net` transport), so it can
// never run on n8n Cloud. We therefore use the non-cloud config (strict mode is
// off in package.json) and additionally skip linting tests, which are not shipped.
export default [...configWithoutCloudSupport, { ignores: ['test/**', 'dist/**'] }];

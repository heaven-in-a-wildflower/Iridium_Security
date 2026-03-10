import pluginSecurity from 'eslint-plugin-security';

export default [
  pluginSecurity.configs.recommended,
  {
    languageOptions: { ecmaVersion: 2022 },
    rules: {
      'security/detect-object-injection':      'warn',
      'security/detect-non-literal-fs-filename': 'warn',
      'security/detect-child-process':          'warn',
      'security/detect-eval-with-expression':   'warn',
      'security/detect-non-literal-require':    'warn',
    }
  }
];

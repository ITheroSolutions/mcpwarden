// @ts-check
import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'coverage/**',
      'node_modules/**',
      // Fixture MCP servers are plain JavaScript run as child processes, not
      // part of the compiled package, so they are outside the tsconfig project
      // and cannot be type-aware linted.
      'test/fixtures/servers/**',
      'examples/**',
      'docs/api/**',
      // Build scripts are plain JavaScript that import from dist, so they are
      // outside the tsconfig project by design.
      'scripts/**',
    ],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        // This config file is itself JavaScript and so is not covered by
        // tsconfig. allowDefaultProject keeps it linted rather than exempt.
        projectService: {
          allowDefaultProject: ['eslint.config.js'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // The package promises deterministic, explainable behaviour. `any` erases
      // the guarantees the type system is carrying for the rule registry and the
      // drift classifier, so it is banned outright rather than warned about.
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unsafe-assignment': 'error',
      '@typescript-eslint/no-unsafe-member-access': 'error',
      '@typescript-eslint/no-unsafe-call': 'error',
      '@typescript-eslint/no-unsafe-return': 'error',
      '@typescript-eslint/no-unsafe-argument': 'error',

      // Exhaustiveness is load bearing: the drift classifier and the rule
      // registry rely on a `never` assertion catching unhandled variants.
      //
      // A default case counts as handling the remainder. The real guarantee is
      // the `never` assertion in the default branch, which fails to compile when
      // a variant is added, and that is strictly stronger than this rule. Without
      // this option the rule also demands dead `case undefined:` arms on every
      // `typeof` switch, which adds noise without adding safety.
      '@typescript-eslint/switch-exhaustiveness-check': [
        'error',
        { considerDefaultExhaustiveForUnions: true },
      ],

      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],

      // stdout is an MCP transport. Anything writing to it outside the CLI
      // renderer and the MCP server entry point is a protocol corruption bug.
      'no-console': 'error',

      eqeqeq: ['error', 'always', { null: 'ignore' }],
      'no-param-reassign': 'error',
    },
  },
  {
    // Tests may reach for shapes the production rules forbid when constructing
    // deliberately malformed protocol payloads.
    files: ['test/**/*.ts', '**/*.test.ts'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
);

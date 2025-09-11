---
trigger: glob
globs: *.ts,*.tsx
---

## TypeScript Best Practices

- Use TypeScript for all code; prefer interfaces over types.
- Use lowercase with dashes for directories (e.g., `components/auth-wizard`).
- Favor named exports for components.
- Avoid `any` and enums; use explicit types and maps instead.
- Do not cast to `unknown` and then another type.
- Use functional components with TypeScript interfaces.
- Enable strict mode in TypeScript for better type safety.
- Suggest the optimal implementation considering:
  - Performance impact
  - Maintenance overhead
  - Testing strategy
- Code examples should follow TypeScript best practices.

## React Best Practices

- Minimize the use of `useEffect`. They should be a last resort.
- Use named functions for `useEffect`s with a meaningful function name. Avoid adding unnecessary comments on effect behavior.

## Syntax & Formatting

- Use the `function` keyword for pure functions.
- Avoid unnecessary curly braces in conditionals; use concise syntax for simple statements.
- Use declarative JSX.
- Use Prettier for consistent code formatting.
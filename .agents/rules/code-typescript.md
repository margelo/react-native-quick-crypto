# TypeScript Rules

Applies to `*.ts` and `*.tsx`.

## Blocking

- No `any`. Create proper interfaces/types.
- If shape is truly dynamic, validate with type guards.
- Avoid `(value as unknown) as Type`; write a guard instead.
- Chai assertions must satisfy `@typescript-eslint/no-unused-expressions`.

## Strict

- Prefer interfaces for object shapes.
- Use named exports; avoid default exports.
- Avoid enums; use explicit unions/maps.
- Write explicit return types.
- Keep functions minimal and modular.
- Use Bun for package management; do not use npm/yarn/pnpm.
- For React, minimize `useEffect`; use named effect functions if unavoidable.

## Formatting

- Use `function` for pure functions.
- Prefer concise conditionals when clear.
- Use declarative JSX.
- Let Prettier handle formatting.

## Chai Patterns

Use:

```ts
expect(value).to.equal(expected);
expect(value).to.match(/^[A-Za-z0-9_-]+$/);
assert.isFalse(value.endsWith("."));
```

Avoid:

```ts
expect(value).to.exist;
expect(value).to.not.be.undefined;
expect(value.endsWith(".")).to.be.false;
```

Adding an assertion message does not fix unused-expression lint failures.

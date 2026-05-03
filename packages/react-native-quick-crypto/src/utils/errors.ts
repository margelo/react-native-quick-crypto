type DOMName =
  | string
  | {
      name: string;
      cause: unknown;
    };

// Hermes (React Native) does not implement DOMException natively. Use it when
// the host provides one; otherwise fall back to an Error subclass that exposes
// the WebCrypto-relevant surface (.name, .message, .code) so consumers that
// branch on `err.name === 'InvalidAccessError'` see the spec-correct value.
const DOM_EXCEPTION_CODES: Record<string, number> = {
  IndexSizeError: 1,
  HierarchyRequestError: 3,
  WrongDocumentError: 4,
  InvalidCharacterError: 5,
  NoModificationAllowedError: 7,
  NotFoundError: 8,
  NotSupportedError: 9,
  InUseAttributeError: 10,
  InvalidStateError: 11,
  SyntaxError: 12,
  InvalidModificationError: 13,
  NamespaceError: 14,
  InvalidAccessError: 15,
  TypeMismatchError: 17,
  SecurityError: 18,
  NetworkError: 19,
  AbortError: 20,
  URLMismatchError: 21,
  QuotaExceededError: 22,
  TimeoutError: 23,
  InvalidNodeTypeError: 24,
  DataCloneError: 25,
};

const HostDOMException: typeof globalThis.DOMException | undefined = (
  globalThis as { DOMException?: typeof globalThis.DOMException }
).DOMException;

class FallbackDOMException extends Error {
  readonly code: number;
  constructor(message: string, name: string) {
    super(message);
    this.name = name;
    this.code = DOM_EXCEPTION_CODES[name] ?? 0;
  }
}

export function lazyDOMException(message: string, domName: DOMName): Error {
  const name = typeof domName === 'string' ? domName : domName.name;
  const cause = typeof domName === 'string' ? undefined : domName.cause;

  let err: Error;
  if (HostDOMException) {
    err =
      cause !== undefined
        ? new HostDOMException(message, { name, cause } as never)
        : new HostDOMException(message, name);
  } else {
    err = new FallbackDOMException(message, name);
    if (cause !== undefined) {
      (err as Error & { cause?: unknown }).cause = cause;
    }
  }
  return err;
}

// QuotaExceededError carries `quota` and `requested` numeric fields per the
// WebIDL spec (https://webidl.spec.whatwg.org/#quotaexceedederror). DOMException
// in legacy hosts does not expose these, so always use our subclass.
export class QuotaExceededError extends FallbackDOMException {
  readonly quota: number | null;
  readonly requested: number | null;
  constructor(
    message: string,
    options: { quota?: number; requested?: number } = {},
  ) {
    super(message, 'QuotaExceededError');
    this.quota = options.quota ?? null;
    this.requested = options.requested ?? null;
  }
}

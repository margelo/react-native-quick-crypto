type DOMName =
  | string
  | {
      name: string;
      cause: unknown;
    };

export function lazyDOMException(message: string, domName: DOMName): Error {
  let cause = '';
  if (typeof domName !== 'string') {
    cause = `\nCaused by: ${domName.cause}`;
  }

  return new Error(`[${domName}]: ${message}${cause}`);
}

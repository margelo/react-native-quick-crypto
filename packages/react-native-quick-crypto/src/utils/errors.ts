type DOMName =
  | string
  | {
      name: string;
      cause: unknown;
    };

export function lazyDOMException(message: string, domName: DOMName): Error {
  const name = typeof domName === 'string' ? domName : domName.name;
  const cause =
    typeof domName === 'string' ? '' : `\nCaused by: ${domName.cause}`;
  return new Error(`[${name}]: ${message}${cause}`);
}

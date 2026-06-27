declare module "react" {
  export type ReactNode = unknown;
  export type Dispatch<T> = (value: T) => void;
  export type SetStateAction<T> = T | ((previous: T) => T);
  export function createElement(type: unknown, props?: Record<string, unknown> | null, ...children: ReactNode[]): unknown;
  export function useEffect(effect: () => void | (() => void), deps?: unknown[]): void;
  export function useMemo<T>(factory: () => T, deps: unknown[]): T;
  export function useState<T>(initial: T | (() => T)): [T, (value: SetStateAction<T>) => void];
}

declare module "react-dom/client" {
  export interface Root {
    render(element: unknown): void;
    unmount(): void;
  }
  export function createRoot(container: Element | DocumentFragment): Root;
}

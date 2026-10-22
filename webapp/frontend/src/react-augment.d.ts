// Module augmentation for 'react' to add named exports
// This works around the fact that @types/react uses "export = React"

import * as React from 'react';

declare module 'react' {
  // Re-export all types from the React namespace as named exports
  export type ReactElement = React.ReactElement;
  export type ReactNode = React.ReactNode;
  export type ReactFragment = React.ReactFragment;
  export type ReactPortal = React.ReactPortal;
  export type Component<P = {}> = React.Component<P>;
  export type ComponentClass<P = {}> = React.ComponentClass<P>;
  export type FunctionComponent<P = {}> = React.FunctionComponent<P>;
  export type ComponentProps<T extends React.ElementType> = React.ComponentProps<T>;
  export type ComponentPropsWithoutRef<T extends React.ElementType> = React.ComponentPropsWithoutRef<T>;
  export type ComponentPropsWithRef<T extends React.ElementType> = React.ComponentPropsWithRef<T>;
  export type ElementType = React.ElementType;
  export type JSXElementConstructor<P> = React.JSXElementConstructor<P>;
  export type Dispatch<A> = React.Dispatch<A>;
  export type SetStateAction<S> = React.SetStateAction<S>;
  export type EffectCallback = React.EffectCallback;
  export type DependencyList = React.DependencyList;
  export type Ref<T> = React.Ref<T>;
  export type RefObject<T> = React.RefObject<T>;
  export type MutableRefObject<T> = React.MutableRefObject<T>;
  export type ForwardRefExoticComponent<P> = React.ForwardRefExoticComponent<P>;
  export type PropsWithoutRef<P> = React.PropsWithoutRef<P>;
  export type RefAttributes<T> = React.RefAttributes<T>;
  export type Key = React.Key;
  export type HTMLAttributes<T> = React.HTMLAttributes<T>;
  export type DetailedHTMLProps<E extends HTMLElement, P> = React.DetailedHTMLProps<E, P>;
  export type MouseEvent<T = Element> = React.MouseEvent<T>;
  export type KeyboardEvent<T = Element> = React.KeyboardEvent<T>;
  export type ChangeEvent<T = Element> = React.ChangeEvent<T>;
  export type FocusEvent<T = Element> = React.FocusEvent<T>;
  export type FormEvent<T = Element> = React.FormEvent<T>;
  export type ClipboardEvent<T = Element> = React.ClipboardEvent<T>;
  export type CompositionEvent<T = Element> = React.CompositionEvent<T>;
  export type DragEvent<T = Element> = React.DragEvent<T>;
  export type PointerEvent<T = Element> = React.PointerEvent<T>;
  export type TouchEvent<T = Element> = React.TouchEvent<T>;
  export type WheelEvent<T = Element> = React.WheelEvent<T>;
  export type AnimationEvent<T = Element> = React.AnimationEvent<T>;
  export type TransitionEvent<T = Element> = React.TransitionEvent<T>;
  export type UIEvent<T = Element> = React.UIEvent<T>;
  export type SyntheticEvent<T = Element, E = Event> = React.SyntheticEvent<T, E>;

  // Re-export hooks as named exports
  export function useState<S>(initialState: S | (() => S)): [S, React.Dispatch<React.SetStateAction<S>>];
  export function useState<S = undefined>(): [S | undefined, React.Dispatch<React.SetStateAction<S | undefined>>];
  export function useEffect(effect: React.EffectCallback, deps?: React.DependencyList): void;
  export function useRef<T>(initialValue: T | null): React.MutableRefObject<T>;
  export function useCallback<F extends Function>(callback: F, deps: React.DependencyList): F;
  export function useMemo<T>(factory: () => T, deps: React.DependencyList): T;
  export function useContext<T>(context: React.Context<T>): T;
  export function useReducer<R, I>(reducer: React.Reducer<R, I>, initialArg: I, init?: (arg: I) => R): [R, React.Dispatch<I>];
  export function useLayoutEffect(effect: React.EffectCallback, deps?: React.DependencyList): void;
  export function useImperativeHandle<T, R extends T>(ref: React.Ref<T> | null, init: () => R, deps?: React.DependencyList): void;
  export function useDebugValue<T>(value: T, formatter?: (value: T) => any): void;
  export function useId(): string;
  export function useSyncExternalStore<Snapshot>(subscribe: (callback: () => void) => () => void, getSnapshot: () => Snapshot, getServerSnapshot?: () => Snapshot): Snapshot;
  export function useInsertionEffect(effect: React.EffectCallback, deps?: React.DependencyList): void;
  export function useDeferredValue<T>(value: T): T;
  export function useTransition(): [boolean, (callback: () => void) => void];
  export function useOptimistic<T>(state: T, update: (state: T, action: any) => T): [T, (action: any) => void];

  // Re-export other React APIs
  export function createElement<P extends {}>(type: React.ElementType<P>, props?: P | null, ...children: React.ReactNode[]): React.ReactElement<P>;
  export function cloneElement<P>(element: React.ReactElement<P>, props?: Partial<P> | null, ...children: React.ReactNode[]): React.ReactElement<P>;
  export function createFactory<P>(type: React.ElementType<P>): (props?: P | null, ...children: React.ReactNode[]) => React.ReactElement<P>;
  export function isValidElement<P>(object: {}): object is React.ReactElement<P>;
  export const version: string;
  export const Children: React.Children;
  export const Fragment: React.Fragment;
  export const StrictMode: React.ComponentType<{ children: React.ReactNode }>;
  export const Profiler: React.ComponentType<React.ProfilerProps>;
  export const Suspense: React.ComponentType<{ children: React.ReactNode; fallback: React.ReactNode }>;
  export function lazy<P>(ctor: () => Promise<React.ComponentType<P>>): React.LazyExoticComponent<React.ComponentType<P>>;
  export function memo<P>(Component: React.ComponentType<P>, propsAreEqual?: (prev: P, next: P) => boolean): React.MemoExoticComponent<React.ComponentType<P>>;
  export function forwardRef<T, P = {}>(render: (props: P, ref: React.Ref<T>) => React.ReactElement | null): React.ForwardRefExoticComponent<React.PropsWithoutRef<P> & React.RefAttributes<T>>;
  export function createContext<T>(defaultValue: T): React.Context<T>;
  export function createRef<T>(): React.RefObject<T>;
  export function startTransition(scope: () => void): void;
  export function use<T>(usable: React.Usable<T>): T;
}
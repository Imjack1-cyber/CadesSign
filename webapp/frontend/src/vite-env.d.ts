/// <reference types="vite/client" />
/// <reference types="@siemens/ix-react" />

declare module 'react' {
  // Ensure React namespace has the required methods
  namespace React {
    function createElement<P extends {}>(type: string | React.JSXElementConstructor<P>, props?: P | null, ...children: React.ReactNode[]): React.ReactElement<P>;
    function forwardRef<T, P = {}>(render: (props: P, ref: React.Ref<T>) => React.ReactElement | null): React.ForwardRefExoticComponent<React.PropsWithoutRef<P> & React.RefAttributes<T>>;
  }
}

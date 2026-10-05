// Adapter for Mailspring `app/src/components/injected-component.tsx` +
// `injected-component-set.tsx`. KIWI has no ComponentRegistry/extension
// loader, so `matching`/`exposedProps`/`matchLimit` are accepted for API
// parity but never resolve to plugins:
//  - `InjectedComponent` renders its `fallback` component with exposedProps
//    (exactly the vendor's no-match path: "component = components.length
//    === 0 ? this.props.fallback : components[0]", with components always
//    empty), or an empty div when no fallback is given.
//  - `InjectedComponentSet` renders `children` inside the same Flexbox-ish
//    container the vendor uses (row by default, `direction` prop honored).
import React from "react";
import { Utils } from "./ms-exports";

type InjectedComponentProps = {
  matching: Record<string, unknown>;
  className?: string;
  exposedProps?: any;
  fallback?: React.ComponentType<any>;
  style?: React.CSSProperties;
  requiredMethods?: string[];
  onComponentDidChange?: (...args: any[]) => any;
};

export class InjectedComponent extends React.Component<InjectedComponentProps> {
  static displayName = "InjectedComponent";

  static defaultProps = {
    style: {},
    className: "",
    exposedProps: {},
    requiredMethods: [],
    onComponentDidChange: () => {},
  };

  render() {
    const Component = this.props.fallback;
    if (!Component) {
      return <div />;
    }
    const exposedProps = Object.assign({}, this.props.exposedProps, {
      fallback: this.props.fallback,
    });
    // Vendor routes container-free components straight out; ours always
    // takes that path since no registry match can ever wrap it.
    return <Component {...exposedProps} />;
  }
}

type InjectedComponentSetProps = React.HTMLProps<HTMLDivElement> & {
  matching?: Record<string, unknown>;
  matchLimit?: number;
  exposedProps?: any;
  containersRequired?: boolean;
  deferred?: boolean;
  inline?: boolean;
  direction?: "row" | "column";
};

export class InjectedComponentSet extends React.Component<InjectedComponentSetProps> {
  static displayName = "InjectedComponentSet";

  static ownPropKeys = [
    "matching",
    "children",
    "className",
    "matchLimit",
    "exposedProps",
    "containersRequired",
    "deferred",
    "inline",
  ];

  static defaultProps = {
    direction: "row" as const,
    className: "",
    exposedProps: {},
    containersRequired: true,
  };

  render() {
    const { children, direction } = this.props;
    const flexboxProps = Utils.fastOmit(this.props, InjectedComponentSet.ownPropKeys);
    return (
      <div
        {...flexboxProps}
        style={{
          display: this.props.inline ? "inline-flex" : "flex",
          flexDirection: direction === "column" ? "column" : "row",
          ...this.props.style,
        }}
      >
        {children}
      </div>
    );
  }
}

export default InjectedComponent;
